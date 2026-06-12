"""
firewall_audit_logger.py
=========================
PostgreSQL persistence layer for AegisOps MCP Firewall verdicts.

Writes every firewall inspection result to the ``firewall_audit_log``
table for compliance, forensics, and post-incident RCA enrichment.
Also supports aggregation queries for dashboarding and Splunk HEC
ingestion of audit events.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

import httpx

from db_config import get_db_connection
from mcp_firewall import FirewallAuditEntry


class FirewallAuditLogger:
    """Handles persistence of firewall verdicts to PostgreSQL and
    optional forwarding to Splunk via HTTP Event Collector (HEC).

    Attributes:
        splunk_hec_url: Optional Splunk HEC endpoint URL. If set,
            every verdict is also shipped as a JSON event to Splunk.
        splunk_hec_token: Optional HEC authentication token.
    """

    def __init__(
        self,
        splunk_hec_url: Optional[str] = None,
        splunk_hec_token: Optional[str] = None,
    ) -> None:
        self.splunk_hec_url = splunk_hec_url or os.getenv("SPLUNK_HEC_URL")
        self.splunk_hec_token = splunk_hec_token or os.getenv("SPLUNK_HEC_TOKEN")

    def log_verdict(
        self, incident_id: str, audit_entry: FirewallAuditEntry
    ) -> None:
        """Persists a firewall verdict to the ``firewall_audit_log`` table.

        Args:
            incident_id: The active incident thread ID.
            audit_entry: The structured audit record from the firewall.
        """
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO firewall_audit_log (
                        incident_id, tool_name, tool_args,
                        entropy_score, privilege_score, deviation_score,
                        injection_match, frequency_score,
                        composite_risk, verdict, matched_rules
                    ) VALUES (
                        %s, %s, %s::jsonb,
                        %s, %s, %s,
                        %s, %s,
                        %s, %s, %s::jsonb
                    );
                    """,
                    (
                        incident_id,
                        audit_entry.tool_name,
                        json.dumps(audit_entry.tool_args, default=str),
                        audit_entry.entropy_score,
                        audit_entry.privilege_score,
                        audit_entry.deviation_score,
                        audit_entry.injection_match,
                        audit_entry.frequency_score,
                        audit_entry.composite_risk,
                        audit_entry.verdict,
                        json.dumps(audit_entry.matched_rules),
                    ),
                )
            print(
                f"[Firewall Audit] Logged verdict={audit_entry.verdict} "
                f"for tool={audit_entry.tool_name} "
                f"(risk={audit_entry.composite_risk:.3f}) "
                f"on incident={incident_id}"
            )
        finally:
            conn.close()

        # Optionally forward to Splunk HEC
        self._ship_to_splunk_hec(incident_id, audit_entry)

    def get_incident_verdicts(self, incident_id: str) -> List[Dict[str, Any]]:
        """Retrieves all firewall decisions for an incident.

        Used by the resolution node to include firewall audit data
        in the final RCA report.

        Args:
            incident_id: The incident to query.

        Returns:
            List of verdict dictionaries ordered by creation time.
        """
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT tool_name, tool_args, entropy_score,
                           privilege_score, deviation_score,
                           injection_match, frequency_score,
                           composite_risk, verdict, matched_rules,
                           created_at
                    FROM firewall_audit_log
                    WHERE incident_id = %s
                    ORDER BY created_at ASC;
                    """,
                    (incident_id,),
                )
                rows = cur.fetchall()
                return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_block_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Aggregates block counts by tool name over a time window.

        Useful for dashboarding and trend analysis of firewall
        enforcement patterns.

        Args:
            hours: Lookback window in hours.

        Returns:
            Dictionary with ``total_blocks``, ``total_quarantines``,
            and ``by_tool`` breakdown.
        """
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT tool_name, verdict, COUNT(*) as count
                    FROM firewall_audit_log
                    WHERE created_at >= NOW() - INTERVAL '%s hours'
                      AND verdict IN ('BLOCK', 'QUARANTINE')
                    GROUP BY tool_name, verdict
                    ORDER BY count DESC;
                    """,
                    (hours,),
                )
                rows = cur.fetchall()

                summary: Dict[str, Any] = {
                    "total_blocks": 0,
                    "total_quarantines": 0,
                    "by_tool": {},
                }
                for row in rows:
                    tool = row["tool_name"]
                    verdict = row["verdict"]
                    count = row["count"]

                    if verdict == "BLOCK":
                        summary["total_blocks"] += count
                    elif verdict == "QUARANTINE":
                        summary["total_quarantines"] += count

                    if tool not in summary["by_tool"]:
                        summary["by_tool"][tool] = {"BLOCK": 0, "QUARANTINE": 0}
                    summary["by_tool"][tool][verdict] = count

                return summary
        finally:
            conn.close()

    def _ship_to_splunk_hec(
        self, incident_id: str, audit_entry: FirewallAuditEntry
    ) -> None:
        """Forwards the audit entry to Splunk HTTP Event Collector.

        Formats the entry as a JSON-RPC 2.0 log envelope conforming
        to the Splunk Technology Add-on for MCP (App ID 8377) schema.

        Fails silently if HEC is not configured or unreachable,
        logging a warning rather than blocking the firewall pipeline.

        Args:
            incident_id: The active incident ID.
            audit_entry: The audit entry to ship.
        """
        if not self.splunk_hec_url or not self.splunk_hec_token:
            return  # HEC not configured — skip silently

        hec_event = {
            "event": audit_entry.to_jsonrpc_log(incident_id),
            "sourcetype": "aegisops:firewall:verdict",
            "source": "aegisops_mcp_firewall",
            "index": "main",
            "time": time.time(),
        }

        try:
            with httpx.Client(timeout=3.0) as client:
                client.post(
                    self.splunk_hec_url,
                    headers={
                        "Authorization": f"Splunk {self.splunk_hec_token}",
                        "Content-Type": "application/json",
                    },
                    json=hec_event,
                )
        except Exception as e:
            print(
                f"[Firewall Audit] WARNING: Failed to ship to Splunk HEC: {e}"
            )
