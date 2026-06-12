"""
gated_tools.py
===============
Gated tool execution router for AegisOps.

Intercepts every tool call from the LLM agent, validates against
Redis procedural policies for local tools, and routes MCP-bound
tools (Splunk) through the Semantic MCP Firewall proxy.

Architecture:
    LLM Agent emits tool_calls
         │
         ▼
    gated_tool_executor()
         │
         ├── Local tool (get_logs, restart_deployment, etc.)
         │       └──► ProceduralMemoryManager.verify_action_permissions()
         │               └──► Execute or dispatch Slack HITL
         │
         └── MCP tool (splunk_run_query, etc.)
                 └──► SecureMCPProxy.call_tool()
                         └──► MCPFirewall.evaluate() → ALLOW/QUARANTINE/BLOCK
"""

import json
import time
from typing import Any, Dict, List, Optional

from langchain_core.messages import ToolMessage
from langgraph.prebuilt import InjectedState

from state import AegisOpsState
from procedural_memory import ProceduralMemoryManager
from tools_config import tools_by_name
from slack_client import dispatch_slack_approval_block


async def gated_tool_executor(state: AegisOpsState) -> Dict[str, Any]:
    """Gated tool router. Intercepts calls, validates against Redis policies,
    and routes MCP tools through the Semantic MCP Firewall proxy.

    For local tools: checks procedural memory policies and prompts
    Slack HITL workflows if approval is needed.

    For MCP tools: delegates to the SecureMCPProxy which runs the
    full 5-dimensional risk scoring pipeline before forwarding.
    """

    # Extract the last message which contains the requested tool calls
    last_message = state["messages"][-1]
    if not hasattr(last_message, "tool_calls") or not last_message.tool_calls:
        return {"messages": []}

    outputs: List[ToolMessage] = []
    tool_audit: List[Dict[str, Any]] = []
    firewall_audit: List[Dict[str, Any]] = []

    # Detect MCP-bound tools: names prefixed with "splunk_" or discovered
    # via MCP tools/list (stored in state by graph_builder initialization)
    mcp_tool_names: List[str] = state.get("_mcp_tool_names", [])
    mcp_proxy: Optional[Any] = state.get("_mcp_proxy")

    for tool_call in last_message.tool_calls:
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]
        tool_id = tool_call["id"]

        print(f"[{state['incident_id']}] Evaluating Policy for: {tool_name} with args {tool_args}")

        # Inject context-sensitive parameters if they are missing
        if "service_name" not in tool_args:
            tool_args["service_name"] = state["service_name"]
        if "namespace" not in tool_args:
            tool_args["namespace"] = state["namespace"]

        start_time = time.time()

        # ── Route Decision: MCP Tool vs. Local Tool ───────────────────
        is_mcp_tool = (
            tool_name.startswith("splunk_")
            or tool_name in ("run_splunk_query", "search_splunk", "generate_spl")
            or tool_name in mcp_tool_names
        )

        if is_mcp_tool and mcp_proxy is not None:
            # ── MCP Tool: Route through Semantic MCP Firewall ─────────
            result = await _execute_mcp_tool(
                mcp_proxy, tool_name, tool_args, state, firewall_audit
            )
            status = "Firewall-Evaluated"
            latency = time.time() - start_time
        else:
            # ── Local Tool: Use existing procedural policy engine ─────
            result, status = await _execute_local_tool(
                tool_name, tool_args, state
            )
            latency = time.time() - start_time

        # ── Compile audit payload ─────────────────────────────────────
        audit_entry = {
            "tool": tool_name,
            "args": tool_args,
            "status": status,
            "latency_seconds": round(latency, 3),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        tool_audit.append(audit_entry)

        outputs.append(
            ToolMessage(
                content=str(result),
                tool_call_id=tool_id,
                name=tool_name,
            )
        )

    result_state: Dict[str, Any] = {
        "messages": outputs,
        "tool_audit_trail": tool_audit,
    }
    if firewall_audit:
        result_state["firewall_audit_trail"] = firewall_audit

    return result_state


async def _execute_mcp_tool(
    mcp_proxy: Any,
    tool_name: str,
    tool_args: dict,
    state: AegisOpsState,
    firewall_audit: List[Dict[str, Any]],
) -> str:
    """Routes a tool call through the Secure MCP Proxy.

    The proxy runs the full firewall evaluation pipeline (entropy,
    privilege, deviation, injection, frequency) and returns either
    the tool result or a block message.

    Args:
        mcp_proxy: The active ``SecureMCPProxy`` instance.
        tool_name: The MCP tool name.
        tool_args: The tool arguments.
        state: The current graph state.
        firewall_audit: Mutable list to append audit entries to.

    Returns:
        The tool execution result or firewall block message.
    """
    try:
        result = await mcp_proxy.call_tool(tool_name, tool_args)

        # Extract the last audit entry from the proxy's logger for state tracking
        # (the proxy persists to PostgreSQL internally, but we also want it in state)
        firewall_audit.append({
            "tool": tool_name,
            "args": tool_args,
            "source": "mcp_firewall",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

        # Handle MCP result formats
        if hasattr(result, "content"):
            # MCP result object with content array
            content_parts = result.content if isinstance(result.content, list) else [result.content]
            text_parts = []
            for part in content_parts:
                if hasattr(part, "text"):
                    text_parts.append(part.text)
                else:
                    text_parts.append(str(part))
            return "\n".join(text_parts) if text_parts else str(result)
        return str(result)

    except Exception as e:
        return f"MCP Tool Execution Error: {str(e)}"


async def _execute_local_tool(
    tool_name: str,
    tool_args: dict,
    state: AegisOpsState,
) -> tuple:
    """Executes a local LangGraph tool with procedural policy gating.

    Preserves the original gating logic: checks Redis policies,
    routes to Slack HITL if approval is required, or blocks if
    the policy forbids the action.

    Args:
        tool_name: The local tool name.
        tool_args: The tool arguments.
        state: The current graph state.

    Returns:
        Tuple of (result_string, status_string).
    """
    try:
        # Query Procedural Memory (Redis Cache Validator)
        is_allowed_autonomous = ProceduralMemoryManager.verify_action_permissions(
            service_name=state["service_name"],
            requested_action=tool_name,
        )

        if is_allowed_autonomous:
            # Execute autonomously
            result = await tools_by_name[tool_name].ainvoke(tool_args)
            return (result, "Executed")
        else:
            # L3 Human-In-The-Loop Approval Gate Triggered
            print(
                f"[{state['incident_id']}] HITL Triggered: "
                f"Pausing execution. Dispatching Slack Approval..."
            )

            # Push the Block Kit UI payload to Slack
            dispatch_slack_approval_block(
                incident_id=state["incident_id"],
                service=state["service_name"],
                action=tool_name,
                args=tool_args,
                thread_id=state["incident_id"],
            )

            result = (
                f"CRITICAL STATE: This action ({tool_name}) requires human "
                f"operator validation. The graph execution has been paused "
                f"and a manual sign-off request has been sent to Slack. "
                f"Await manual approval."
            )
            return (result, "Paused")

    except Exception as e:
        return (f"Tool Execution Aborted: {str(e)}", "Blocked")
