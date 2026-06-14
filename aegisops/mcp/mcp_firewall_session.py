"""
mcp_firewall_session.py
========================
Session-scoped state tracker for the AegisOps Semantic MCP Firewall.

Maintains rolling semantic intent centroids, call frequency windows,
tool schema snapshots for rug-pull detection, and phase-aware centroid
resets to avoid false positives during SRE workflow phase transitions
(diagnostic → remediation).

Thread-safe: designed for single-session, single-incident usage within
one LangGraph workflow execution.
"""

import time
import hashlib
import json
import numpy as np
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Deque


@dataclass
class FirewallCallRecord:
    """A single timestamped record of a tool call for frequency analysis."""
    tool_name: str
    timestamp: float
    verdict: str  # "ALLOW", "QUARANTINE", "BLOCK"


@dataclass
class FirewallSessionContext:
    """Maintains per-incident session state for the MCP firewall.

    Tracks the semantic intent centroid (rolling mean of tool call
    embeddings), call frequency windows, and tool schema snapshots
    for rug-pull detection.

    Attributes:
        session_id: Tied to the incident thread ID for state isolation.
        intent_centroid: Rolling mean of all tool call embeddings in
            this session. Updated incrementally after every ALLOWed call.
        call_history: Bounded deque of recent call records for frequency
            analysis. Auto-evicts entries older than ``history_window_seconds``.
        tool_schemas_snapshot: Frozen copy of tool schemas from the first
            ``tools/list`` response. Used as the rug-pull detection baseline.
        total_calls: Session lifetime counter across all verdicts.
        blocked_count: Running count of BLOCKed requests.
        quarantine_count: Running count of QUARANTINEd requests.
        phase: Current SRE workflow phase (``diagnostic`` or ``remediation``).
            Used for centroid reset logic to prevent false positives during
            natural workflow transitions.
        embedding_count: Number of embeddings that have been folded into
            the centroid (used for incremental mean calculation).
        history_window_seconds: Size of the sliding window for frequency
            analysis. Defaults to 60 seconds.
    """

    session_id: str
    intent_centroid: Optional[np.ndarray] = None
    call_history: Deque[FirewallCallRecord] = field(
        default_factory=lambda: deque(maxlen=500)
    )
    tool_schemas_snapshot: Dict[str, str] = field(default_factory=dict)
    total_calls: int = 0
    blocked_count: int = 0
    quarantine_count: int = 0
    phase: str = "diagnostic"
    embedding_count: int = 0
    history_window_seconds: float = 60.0

    # Secondary centroid for the remediation phase
    _remediation_centroid: Optional[np.ndarray] = field(
        default=None, repr=False
    )
    _remediation_embedding_count: int = field(default=0, repr=False)

    def update_centroid(self, embedding: np.ndarray) -> None:
        """Incrementally updates the phase-appropriate intent centroid.

        Uses Welford's online mean algorithm to avoid storing all past
        embeddings in memory:

            centroid_new = centroid_old + (embedding - centroid_old) / n

        When the session is in ``remediation`` phase, the secondary
        centroid is updated instead, allowing diagnostic-phase queries
        to not be penalized for the natural semantic shift.

        Args:
            embedding: The 768-dimensional embedding vector for the
                current tool call's arguments.
        """
        if self.phase == "remediation":
            self._remediation_embedding_count += 1
            n = self._remediation_embedding_count
            if self._remediation_centroid is None:
                self._remediation_centroid = embedding.copy()
            else:
                self._remediation_centroid += (
                    (embedding - self._remediation_centroid) / n
                )
        else:
            self.embedding_count += 1
            n = self.embedding_count
            if self.intent_centroid is None:
                self.intent_centroid = embedding.copy()
            else:
                self.intent_centroid += (
                    (embedding - self.intent_centroid) / n
                )

    def get_active_centroid(self) -> Optional[np.ndarray]:
        """Returns the centroid appropriate for the current phase.

        During ``remediation`` phase, returns the remediation centroid
        if it has been initialized; otherwise falls back to the
        diagnostic centroid.
        """
        if self.phase == "remediation" and self._remediation_centroid is not None:
            return self._remediation_centroid
        return self.intent_centroid

    def transition_phase(self, new_phase: str) -> None:
        """Signals a workflow phase transition.

        Resets the secondary centroid so that the new phase starts
        with a clean semantic baseline.

        Args:
            new_phase: The new phase name (``diagnostic`` or ``remediation``).
        """
        self.phase = new_phase
        if new_phase == "remediation":
            self._remediation_centroid = None
            self._remediation_embedding_count = 0

    def record_call(
        self, tool_name: str, verdict: str, timestamp: Optional[float] = None
    ) -> None:
        """Appends a tool call to the sliding frequency window.

        Args:
            tool_name: The MCP tool name that was called.
            verdict: The firewall verdict (``ALLOW``, ``QUARANTINE``, ``BLOCK``).
            timestamp: Unix timestamp. Defaults to ``time.time()`` if not given.
        """
        ts = timestamp if timestamp is not None else time.time()
        self.call_history.append(
            FirewallCallRecord(tool_name=tool_name, timestamp=ts, verdict=verdict)
        )
        self.total_calls += 1
        if verdict == "BLOCK":
            self.blocked_count += 1
        elif verdict == "QUARANTINE":
            self.quarantine_count += 1

    def get_call_rate(self, tool_name: str, window_seconds: float = 10.0) -> float:
        """Returns the calls-per-second rate for a specific tool.

        Only counts calls within the last ``window_seconds``.

        Args:
            tool_name: The tool to measure.
            window_seconds: The lookback window in seconds.

        Returns:
            Calls per second for the specified tool within the window.
        """
        now = time.time()
        cutoff = now - window_seconds
        count = sum(
            1 for record in self.call_history
            if record.tool_name == tool_name and record.timestamp >= cutoff
        )
        return count / window_seconds if window_seconds > 0 else 0.0

    def get_total_rate(self, window_seconds: float = 10.0) -> float:
        """Returns the aggregate calls-per-second rate across all tools.

        Args:
            window_seconds: The lookback window in seconds.

        Returns:
            Total calls per second within the window.
        """
        now = time.time()
        cutoff = now - window_seconds
        count = sum(
            1 for record in self.call_history
            if record.timestamp >= cutoff
        )
        return count / window_seconds if window_seconds > 0 else 0.0

    def snapshot_schemas(self, tools_list: list) -> None:
        """Captures a fingerprint of every tool's schema from ``tools/list``.

        Stores a SHA-256 hash of each tool's serialized schema so that
        subsequent calls to ``detect_schema_drift`` can detect rug-pull
        modifications without storing the full schema objects.

        Args:
            tools_list: List of tool objects from the MCP ``tools/list``
                response. Each must have ``.name`` and ``.inputSchema``
                attributes (or ``input_schema`` dict key).
        """
        for tool in tools_list:
            name = getattr(tool, "name", None) or tool.get("name", "unknown")
            # Build a deterministic representation for hashing
            schema_data = getattr(tool, "inputSchema", None)
            if schema_data is None:
                schema_data = getattr(tool, "input_schema", None)
            if schema_data is None and isinstance(tool, dict):
                schema_data = tool.get("inputSchema", tool.get("input_schema", {}))
            description = getattr(tool, "description", None)
            if description is None and isinstance(tool, dict):
                description = tool.get("description", "")

            fingerprint_source = json.dumps(
                {"name": name, "schema": schema_data, "description": description},
                sort_keys=True,
                default=str,
            )
            self.tool_schemas_snapshot[name] = hashlib.sha256(
                fingerprint_source.encode("utf-8")
            ).hexdigest()

    def detect_schema_drift(self, current_tools_list: list) -> List[str]:
        """Compares current tool schemas against the frozen snapshot.

        Returns the names of any tools whose schema fingerprint has
        changed since the initial snapshot. An empty return value
        means no drift was detected.

        Args:
            current_tools_list: Fresh list of tool objects from a new
                ``tools/list`` call.

        Returns:
            List of tool names whose schemas have drifted.
        """
        if not self.tool_schemas_snapshot:
            return []  # No baseline to compare against

        drifted: List[str] = []
        for tool in current_tools_list:
            name = getattr(tool, "name", None) or tool.get("name", "unknown")
            schema_data = getattr(tool, "inputSchema", None)
            if schema_data is None:
                schema_data = getattr(tool, "input_schema", None)
            if schema_data is None and isinstance(tool, dict):
                schema_data = tool.get("inputSchema", tool.get("input_schema", {}))
            description = getattr(tool, "description", None)
            if description is None and isinstance(tool, dict):
                description = tool.get("description", "")

            fingerprint_source = json.dumps(
                {"name": name, "schema": schema_data, "description": description},
                sort_keys=True,
                default=str,
            )
            current_hash = hashlib.sha256(
                fingerprint_source.encode("utf-8")
            ).hexdigest()

            original_hash = self.tool_schemas_snapshot.get(name)
            if original_hash is not None and current_hash != original_hash:
                drifted.append(name)
            elif original_hash is None:
                # New tool appeared mid-session — also suspicious
                drifted.append(name)

        return drifted
