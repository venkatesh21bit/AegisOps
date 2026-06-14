"""
splunk_hec_shipper.py
======================
Splunk HTTP Event Collector (HEC) integration for AegisOps.

Ships structured telemetry events from the AegisOps agent pipeline
directly into Splunk for native security monitoring and dashboarding.

Event Types:
    - aegisops:firewall:verdict    — MCP Firewall risk score results
    - aegisops:incident:lifecycle  — Incident trigger/pause/resume/close
    - aegisops:tool:execution      — Tool execution audit trail
    - aegisops:otel:filter         — OTel filter rule generation events

Compatible with the Splunk Technology Add-on for MCP (App ID 8377)
event schemas for unified AI agent observability.

Environment Variables:
    SPLUNK_HEC_URL:   Full URL to the HEC endpoint (e.g., https://localhost:8088/services/collector/event)
    SPLUNK_HEC_TOKEN: HEC authentication token.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

import httpx

SPLUNK_HEC_URL = os.getenv(
    "SPLUNK_HEC_URL",
    "https://localhost:8088/services/collector/event",
)
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")


class SplunkHECShipper:
    """Async-compatible Splunk HEC event shipper.

    Batches events and ships them to Splunk with proper sourcetype
    classification. Fails silently when HEC is not configured to
    avoid blocking the agent pipeline.

    Args:
        hec_url: Splunk HEC endpoint URL. Defaults to env var.
        hec_token: HEC authentication token. Defaults to env var.
        verify_ssl: Whether to verify TLS certificates (disable for dev).
    """

    def __init__(
        self,
        hec_url: Optional[str] = None,
        hec_token: Optional[str] = None,
        verify_ssl: bool = False,
    ) -> None:
        self.hec_url = hec_url or SPLUNK_HEC_URL
        self.hec_token = hec_token or SPLUNK_HEC_TOKEN
        self.verify_ssl = verify_ssl

    @property
    def is_configured(self) -> bool:
        """Returns True if HEC credentials are configured."""
        return bool(self.hec_token) and self.hec_token != "88a3bc9a-252f-4af2-810d-c8f9d43f7ba4"

    def ship_event(
        self,
        event_data: dict,
        sourcetype: str = "aegisops:generic",
        source: str = "aegisops_agent",
        index: str = "main",
    ) -> bool:
        """Ships a single event to Splunk HEC synchronously.

        Args:
            event_data: The event payload dictionary.
            sourcetype: Splunk sourcetype for parsing.
            source: Splunk source identifier.
            index: Target Splunk index.

        Returns:
            True if the event was accepted, False otherwise.
        """
        if not self.is_configured:
            print(f"[HEC] (Mock Mode) sourcetype={sourcetype} | {json.dumps(event_data)[:200]}")
            return True

        hec_payload = {
            "event": event_data,
            "sourcetype": sourcetype,
            "source": source,
            "index": index,
            "time": time.time(),
        }

        try:
            with httpx.Client(timeout=3.0, verify=self.verify_ssl) as client:
                response = client.post(
                    self.hec_url,
                    headers={
                        "Authorization": f"Splunk {self.hec_token}",
                        "Content-Type": "application/json",
                    },
                    json=hec_payload,
                )
                return response.status_code == 200
        except Exception as e:
            print(f"[HEC] Ship failed: {e}")
            return False

    async def async_ship_event(
        self,
        event_data: dict,
        sourcetype: str = "aegisops:generic",
        source: str = "aegisops_agent",
        index: str = "main",
    ) -> bool:
        """Ships a single event to Splunk HEC asynchronously.

        Args:
            event_data: The event payload dictionary.
            sourcetype: Splunk sourcetype for parsing.
            source: Splunk source identifier.
            index: Target Splunk index.

        Returns:
            True if the event was accepted, False otherwise.
        """
        if not self.is_configured:
            print(f"[HEC] (Mock Mode) sourcetype={sourcetype} | {json.dumps(event_data)[:200]}")
            return True

        hec_payload = {
            "event": event_data,
            "sourcetype": sourcetype,
            "source": source,
            "index": index,
            "time": time.time(),
        }

        try:
            async with httpx.AsyncClient(timeout=3.0, verify=self.verify_ssl) as client:
                response = await client.post(
                    self.hec_url,
                    headers={
                        "Authorization": f"Splunk {self.hec_token}",
                        "Content-Type": "application/json",
                    },
                    json=hec_payload,
                )
                return response.status_code == 200
        except Exception as e:
            print(f"[HEC] Async ship failed: {e}")
            return False

    def ship_incident_event(
        self,
        incident_id: str,
        service_name: str,
        event_type: str,
        details: Optional[dict] = None,
    ) -> bool:
        """Ships a structured incident lifecycle event.

        Args:
            incident_id: The incident identifier.
            service_name: The affected service.
            event_type: One of: triggered, paused, resumed, resolved.
            details: Additional event context.
        """
        event = {
            "incident_id": incident_id,
            "service_name": service_name,
            "event_type": event_type,
            "details": details or {},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return self.ship_event(event, sourcetype="aegisops:incident:lifecycle")

    def ship_tool_execution(
        self,
        incident_id: str,
        tool_name: str,
        status: str,
        latency_seconds: float,
        args: Optional[dict] = None,
    ) -> bool:
        """Ships a tool execution audit event.

        Args:
            incident_id: The incident context.
            tool_name: The tool that was executed.
            status: Execution status (Executed, Paused, Blocked, etc.).
            latency_seconds: Execution duration.
            args: Tool arguments.
        """
        event = {
            "incident_id": incident_id,
            "tool_name": tool_name,
            "status": status,
            "latency_seconds": round(latency_seconds, 3),
            "args": args or {},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return self.ship_event(event, sourcetype="aegisops:tool:execution")

    def ship_batch(self, events: List[dict], sourcetype: str) -> int:
        """Ships multiple events as a batch to Splunk HEC.

        Args:
            events: List of event payload dictionaries.
            sourcetype: Splunk sourcetype for all events.

        Returns:
            Number of events successfully shipped.
        """
        shipped = 0
        for event_data in events:
            if self.ship_event(event_data, sourcetype=sourcetype):
                shipped += 1
        return shipped


# Module-level singleton for easy access
hec_shipper = SplunkHECShipper()
