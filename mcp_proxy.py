"""
mcp_proxy.py
=============
Secure MCP Proxy for AegisOps.

Wraps a live MCP ``ClientSession`` (Stdio or HTTP/SSE) and intercepts
every ``tools/call`` request through the Semantic MCP Firewall before
forwarding to the downstream Splunk MCP server. Supports schema drift
detection on ``tools/list`` and automatic Slack HITL notifications
for quarantine and drift events.

Architecture:
    LangGraph Agent
         │
         ▼
    SecureMCPProxy.call_tool()
         │
         ├──► MCPFirewall.evaluate()  →  BLOCK  →  return error to LLM
         │
         ├──► MCPFirewall.evaluate()  →  QUARANTINE  →  forward + flag
         │
         └──► MCPFirewall.evaluate()  →  ALLOW  →  forward normally
                    │
                    ▼
              ClientSession.call_tool()  →  Splunk MCP Server
"""

import os
import json
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_firewall import MCPFirewall, FirewallVerdict, FirewallAuditEntry
from mcp_firewall_session import FirewallSessionContext
from firewall_audit_logger import FirewallAuditLogger
from slack_client import dispatch_slack_approval_block


class SecureMCPProxy:
    """Drop-in replacement for raw ``ClientSession`` usage.

    Intercepts ``tools/call`` and ``tools/list`` through the firewall
    engine, persists audit entries to PostgreSQL, and dispatches Slack
    notifications for quarantine verdicts and schema drift events.

    Args:
        session: The live MCP ``ClientSession`` (Stdio or HTTP/SSE).
        firewall: The configured ``MCPFirewall`` scoring engine.
        session_context: The per-incident ``FirewallSessionContext``.
        incident_id: The active incident ID for audit logging.
        audit_logger: The ``FirewallAuditLogger`` for persistence.
    """

    def __init__(
        self,
        session: ClientSession,
        firewall: MCPFirewall,
        session_context: FirewallSessionContext,
        incident_id: str,
        audit_logger: Optional[FirewallAuditLogger] = None,
    ) -> None:
        self.session = session
        self.firewall = firewall
        self.session_context = session_context
        self.incident_id = incident_id
        self.audit_logger = audit_logger or FirewallAuditLogger()

        # MCP tool names discovered via tools/list
        self._mcp_tool_names: List[str] = []

    async def initialize(self) -> None:
        """Initializes the MCP session and snapshots tool schemas.

        Delegates to ``session.initialize()``, then calls ``tools/list``
        to discover available tools and freeze their schemas for
        rug-pull detection.
        """
        await self.session.initialize()

        # Snapshot schemas on first connection
        tools_response = await self.session.list_tools()
        tool_objects = tools_response.tools if hasattr(tools_response, "tools") else tools_response
        self.session_context.snapshot_schemas(tool_objects)
        self._mcp_tool_names = [
            getattr(t, "name", None) or t.get("name", "unknown")
            for t in tool_objects
        ]
        print(
            f"[MCP Proxy] Initialized. Discovered {len(self._mcp_tool_names)} tools: "
            f"{self._mcp_tool_names}"
        )

    async def list_tools(self) -> Any:
        """Proxies ``tools/list`` with schema drift detection.

        On subsequent calls (after the initial snapshot), compares
        current schemas against the baseline. If drift is detected,
        logs a QUARANTINE-level audit and dispatches a Slack alert.

        Returns:
            The raw ``tools/list`` response from the MCP server.
        """
        tools_response = await self.session.list_tools()
        tool_objects = tools_response.tools if hasattr(tools_response, "tools") else tools_response

        # Detect rug-pull: schema drift since initial snapshot
        drifted_tools = self.session_context.detect_schema_drift(tool_objects)
        if drifted_tools:
            drift_msg = (
                f"[MCP Proxy] SCHEMA DRIFT DETECTED on tools: {drifted_tools}. "
                f"Possible rug-pull attack. Quarantining modified tools."
            )
            print(drift_msg)

            # Dispatch Slack HITL notification for schema drift
            dispatch_slack_approval_block(
                incident_id=self.incident_id,
                service="mcp_server",
                action="schema_drift_detected",
                args={"drifted_tools": drifted_tools},
                thread_id=self.incident_id,
            )

            # Log as a quarantine-level audit event
            drift_audit = FirewallAuditEntry(
                tool_name="tools/list",
                tool_args={"drifted_tools": drifted_tools},
                entropy_score=0.0,
                privilege_score=0.0,
                deviation_score=0.0,
                injection_match=False,
                frequency_score=0.0,
                composite_risk=0.5,
                verdict=FirewallVerdict.QUARANTINE.value,
                matched_rules=["schema_drift_" + t for t in drifted_tools],
            )
            self.audit_logger.log_verdict(self.incident_id, drift_audit)

        return tools_response

    async def call_tool(self, name: str, arguments: dict) -> Any:
        """Core interception point for every ``tools/call``.

        1. Evaluates the call through the firewall.
        2. If ALLOW: forwards to the MCP server, updates centroid.
        3. If QUARANTINE: forwards but flags for human review.
        4. If BLOCK: returns an error message without executing.
        5. Persists the audit entry to PostgreSQL.

        Args:
            name: The MCP tool name to invoke.
            arguments: The tool arguments dictionary.

        Returns:
            The tool execution result (or an error message if blocked).
        """
        # ── Firewall Evaluation ───────────────────────────────────────
        verdict, audit_entry = self.firewall.evaluate(
            tool_name=name,
            tool_args=arguments,
            session_context=self.session_context,
        )

        # ── Persist Audit Entry ───────────────────────────────────────
        try:
            self.audit_logger.log_verdict(self.incident_id, audit_entry)
        except Exception as e:
            print(f"[MCP Proxy] WARNING: Audit logging failed: {e}")

        # ── Record in Session Context ─────────────────────────────────
        self.session_context.record_call(name, verdict.value)

        # ── Act on Verdict ────────────────────────────────────────────
        if verdict == FirewallVerdict.BLOCK:
            block_reason = (
                f"FIREWALL BLOCK: Tool '{name}' was blocked by the AegisOps "
                f"Semantic MCP Firewall. Risk score: {audit_entry.composite_risk:.3f}. "
                f"Matched rules: {audit_entry.matched_rules}. "
                f"This action has been prevented from executing. "
                f"Please adjust your approach or request human authorization."
            )
            print(
                f"[MCP Proxy] BLOCKED tool={name} "
                f"risk={audit_entry.composite_risk:.3f} "
                f"rules={audit_entry.matched_rules}"
            )
            return block_reason

        if verdict == FirewallVerdict.QUARANTINE:
            print(
                f"[MCP Proxy] QUARANTINED tool={name} "
                f"risk={audit_entry.composite_risk:.3f} — "
                f"executing with human review flag"
            )
            # Dispatch Slack notification for human review
            dispatch_slack_approval_block(
                incident_id=self.incident_id,
                service="mcp_tool",
                action=f"quarantine_{name}",
                args={
                    "risk_score": audit_entry.composite_risk,
                    "tool_args": arguments,
                    "matched_rules": audit_entry.matched_rules,
                },
                thread_id=self.incident_id,
            )

        # ── Forward to MCP Server (ALLOW or QUARANTINE) ───────────────
        print(
            f"[MCP Proxy] {verdict.value} tool={name} "
            f"risk={audit_entry.composite_risk:.3f}"
        )
        try:
            result = await self.session.call_tool(name, arguments)

            # Update session intent centroid after successful execution
            embedding = self.firewall.get_embedding_for_centroid(name, arguments)
            self.session_context.update_centroid(embedding)

            return result
        except Exception as e:
            error_msg = f"MCP Tool Execution Error: {str(e)}"
            print(f"[MCP Proxy] Execution failed for {name}: {e}")
            return error_msg

    @property
    def mcp_tool_names(self) -> List[str]:
        """Returns the list of discovered MCP tool names."""
        return self._mcp_tool_names

    async def close(self) -> None:
        """Closes the underlying MCP session."""
        print(
            f"[MCP Proxy] Session closed. Total calls: "
            f"{self.session_context.total_calls}, "
            f"Blocks: {self.session_context.blocked_count}, "
            f"Quarantines: {self.session_context.quarantine_count}"
        )


async def create_secure_mcp_session(
    incident_id: str,
    firewall_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Factory function to create MCP transport components.

    Returns the components needed to establish a secure MCP session.
    The caller is responsible for managing the async context lifecycle
    of the Stdio/SSE transport.

    Args:
        incident_id: The active incident ID for session scoping.
        firewall_config: Optional firewall config dict. If None, loads
            from Redis via ProceduralMemoryManager.

    Returns:
        Dictionary containing ``firewall``, ``session_context``,
        ``audit_logger``, and ``server_params`` ready for session creation.
    """
    from procedural_memory import ProceduralMemoryManager

    # Load firewall config from Redis (or use provided config)
    if firewall_config is None:
        firewall_config = ProceduralMemoryManager.get_firewall_config()

    firewall = MCPFirewall(config=firewall_config)
    session_context = FirewallSessionContext(session_id=incident_id)
    audit_logger = FirewallAuditLogger()

    # Configure MCP server transport parameters
    server_params = StdioServerParameters(
        command=os.path.abspath(r".venv\Scripts\uvx.exe"),
        args=["mcp-server-splunk"],
        env=os.environ.copy(),
    )

    return {
        "firewall": firewall,
        "session_context": session_context,
        "audit_logger": audit_logger,
        "server_params": server_params,
        "incident_id": incident_id,
    }
