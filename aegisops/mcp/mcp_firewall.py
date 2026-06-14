"""
mcp_firewall.py
================
Core Semantic MCP Firewall & Risk Scoring Engine for AegisOps.

Implements a 5-dimensional risk analysis model that evaluates every
MCP ``tools/call`` request before it reaches the downstream Splunk
MCP server:

    Risk(r) = w₁·H(entropy) + w₂·P(privilege) + w₃·D(semantic)
            + w₄·I(injection) + w₅·F(frequency)

Verdicts:
    ALLOW       — Risk < allow_threshold (default 0.30)
    QUARANTINE  — allow_threshold ≤ Risk < block_threshold (default 0.70)
    BLOCK       — Risk ≥ block_threshold OR injection pattern matched

Weights and thresholds are dynamically loaded from Redis-cached
``params.yml`` configuration so that sensitivity can be adjusted at
runtime without redeploying.
"""

import math
import time
import json
import hashlib
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sentence_transformers import SentenceTransformer

from aegisops.mcp.mcp_firewall_patterns import get_privilege_score, scan_all_patterns
from aegisops.mcp.mcp_firewall_session import FirewallSessionContext

# Lazy-loaded singleton embedding model (shared with episodic/semantic memory)
_encoder: Optional[SentenceTransformer] = None


def _get_encoder() -> SentenceTransformer:
    """Returns the shared 768-dimensional sentence transformer model.

    Lazy-initializes on first call so the module can be imported
    without incurring model-load latency.
    """
    global _encoder
    if _encoder is None:
        _encoder = SentenceTransformer("all-mpnet-base-v2")
    return _encoder


# ── Verdict Enum ──────────────────────────────────────────────────────────

class FirewallVerdict(str, Enum):
    """Possible firewall outcomes for a tool call."""
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


# ── Audit Entry ───────────────────────────────────────────────────────────

@dataclass
class FirewallAuditEntry:
    """Structured record of a single firewall inspection.

    Contains the full scoring breakdown for auditability and the
    final verdict. Serializable to JSON for PostgreSQL persistence
    and Splunk HEC ingestion.
    """
    tool_name: str
    tool_args: dict
    entropy_score: float
    privilege_score: float
    deviation_score: float
    injection_match: bool
    frequency_score: float
    composite_risk: float
    verdict: str  # FirewallVerdict value
    matched_rules: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    evaluation_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the entry to a flat dictionary for database insertion."""
        return {
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "entropy_score": round(self.entropy_score, 4),
            "privilege_score": round(self.privilege_score, 4),
            "deviation_score": round(self.deviation_score, 4),
            "injection_match": self.injection_match,
            "frequency_score": round(self.frequency_score, 4),
            "composite_risk": round(self.composite_risk, 4),
            "verdict": self.verdict,
            "matched_rules": self.matched_rules,
            "timestamp": self.timestamp,
            "evaluation_latency_ms": round(self.evaluation_latency_ms, 2),
        }

    def to_jsonrpc_log(self, incident_id: str) -> dict:
        """Formats the entry as a JSON-RPC 2.0 log envelope for Splunk HEC.

        Conforms to the Splunk Technology Add-on for MCP (App ID 8377)
        event schema so that firewall verdicts appear natively in Splunk
        security dashboards.
        """
        return {
            "jsonrpc": "2.0",
            "method": "aegisops/firewall_verdict",
            "params": {
                "incident_id": incident_id,
                "tool_name": self.tool_name,
                "tool_args": self.tool_args,
                "risk_scores": {
                    "entropy": round(self.entropy_score, 4),
                    "privilege": round(self.privilege_score, 4),
                    "semantic_deviation": round(self.deviation_score, 4),
                    "injection_match": self.injection_match,
                    "frequency": round(self.frequency_score, 4),
                    "composite": round(self.composite_risk, 4),
                },
                "verdict": self.verdict,
                "matched_rules": self.matched_rules,
                "timestamp": self.timestamp,
            },
        }


# ── Default Configuration ─────────────────────────────────────────────────

DEFAULT_FIREWALL_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "weights": {
        "command_entropy": 0.15,
        "access_privilege": 0.25,
        "semantic_deviation": 0.25,
        "injection_pattern": 0.30,
        "call_frequency": 0.05,
    },
    "thresholds": {
        "allow_below": 0.30,
        "quarantine_below": 0.70,
    },
    "rate_limits": {
        "max_calls_per_10s": 8,
        "max_blocks_per_session": 5,
    },
    "schema_drift": {
        "action": "quarantine",
    },
}


# ── Core Firewall Engine ──────────────────────────────────────────────────

class MCPFirewall:
    """Stateless risk scoring engine for MCP tool calls.

    Orchestrates five independent analyzers to produce a weighted
    composite risk score and a firewall verdict. Configuration
    (weights, thresholds, rate limits) is injected at construction
    time and can be refreshed from Redis at any point.

    Args:
        config: Firewall configuration dictionary. If ``None``, uses
            ``DEFAULT_FIREWALL_CONFIG``.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or DEFAULT_FIREWALL_CONFIG
        self._weights = self.config.get("weights", DEFAULT_FIREWALL_CONFIG["weights"])
        self._thresholds = self.config.get(
            "thresholds", DEFAULT_FIREWALL_CONFIG["thresholds"]
        )
        self._rate_limits = self.config.get(
            "rate_limits", DEFAULT_FIREWALL_CONFIG["rate_limits"]
        )

        # Embedding cache: keyed by SHA-256 of the argument string
        # Avoids re-encoding identical argument patterns
        self._embedding_cache: Dict[str, np.ndarray] = {}

    def reload_config(self, config: Dict[str, Any]) -> None:
        """Hot-reloads firewall configuration from a new dictionary.

        Enables runtime sensitivity adjustment via Redis without
        restarting the agent.
        """
        self.config = config
        self._weights = config.get("weights", DEFAULT_FIREWALL_CONFIG["weights"])
        self._thresholds = config.get(
            "thresholds", DEFAULT_FIREWALL_CONFIG["thresholds"]
        )
        self._rate_limits = config.get(
            "rate_limits", DEFAULT_FIREWALL_CONFIG["rate_limits"]
        )

    def evaluate(
        self,
        tool_name: str,
        tool_args: dict,
        session_context: FirewallSessionContext,
    ) -> Tuple[FirewallVerdict, FirewallAuditEntry]:
        """Orchestrates all analyzers and produces a final verdict.

        This is the main entry point called by ``SecureMCPProxy``
        before every ``tools/call`` is forwarded downstream.

        Args:
            tool_name: The MCP tool name being called.
            tool_args: The arguments dictionary for the tool call.
            session_context: The session-scoped state tracker.

        Returns:
            A tuple of (verdict, audit_entry) where the audit entry
            contains the full scoring breakdown.
        """
        start_time = time.monotonic()

        # ── 1. Injection Pattern Scan (binary gate) ───────────────────
        injection_blocked, matched_rules = scan_all_patterns(tool_name, tool_args)
        injection_score = 1.0 if injection_blocked else 0.0

        # ── 2. Command Entropy ────────────────────────────────────────
        entropy_score = self._compute_command_entropy(tool_args)

        # ── 3. Access Privilege Level ─────────────────────────────────
        privilege_score = self._compute_access_privilege_level(tool_name, tool_args)

        # ── 4. Semantic Deviation ─────────────────────────────────────
        deviation_score = self._compute_semantic_deviation(
            tool_name, tool_args, session_context
        )

        # ── 5. Call Frequency Anomaly ─────────────────────────────────
        frequency_score = self._check_rate_anomaly(tool_name, session_context)

        # ── Composite Risk Score ──────────────────────────────────────
        w = self._weights
        composite = (
            w["command_entropy"] * entropy_score
            + w["access_privilege"] * privilege_score
            + w["semantic_deviation"] * deviation_score
            + w["injection_pattern"] * injection_score
            + w["call_frequency"] * frequency_score
        )
        composite = min(composite, 1.0)

        # ── Verdict Decision ──────────────────────────────────────────
        if injection_blocked:
            # Binary override: instant BLOCK regardless of composite
            verdict = FirewallVerdict.BLOCK
        elif composite >= self._thresholds["quarantine_below"]:
            verdict = FirewallVerdict.BLOCK
        elif composite >= self._thresholds["allow_below"]:
            verdict = FirewallVerdict.QUARANTINE
        else:
            verdict = FirewallVerdict.ALLOW

        # ── Session Block Budget Check ────────────────────────────────
        max_blocks = self._rate_limits.get("max_blocks_per_session", 5)
        if (
            session_context.blocked_count >= max_blocks
            and verdict != FirewallVerdict.BLOCK
        ):
            # Session has exceeded block budget — escalate everything
            # to QUARANTINE to signal potential persistent attack
            if verdict == FirewallVerdict.ALLOW:
                verdict = FirewallVerdict.QUARANTINE
                matched_rules.append("session_block_budget_exceeded")

        evaluation_latency = (time.monotonic() - start_time) * 1000

        audit_entry = FirewallAuditEntry(
            tool_name=tool_name,
            tool_args=tool_args,
            entropy_score=entropy_score,
            privilege_score=privilege_score,
            deviation_score=deviation_score,
            injection_match=injection_blocked,
            frequency_score=frequency_score,
            composite_risk=composite,
            verdict=verdict.value,
            matched_rules=matched_rules,
            evaluation_latency_ms=evaluation_latency,
        )

        return verdict, audit_entry

    # ── Private Analyzers ─────────────────────────────────────────────

    def _compute_command_entropy(self, tool_args: dict) -> float:
        """Computes normalized Shannon entropy of the argument token stream.

        High entropy indicates randomized or obfuscated payloads (typical
        of injection attacks). Low entropy indicates predictable,
        structured arguments (typical of legitimate tool usage).

        The entropy is normalized to [0, 1] by dividing by log₂(N)
        where N is the number of unique tokens.

        Args:
            tool_args: The tool call arguments.

        Returns:
            Normalized entropy score in [0.0, 1.0].
        """
        # Flatten all argument values into a token stream
        tokens: List[str] = []
        for value in tool_args.values():
            if isinstance(value, str):
                # Tokenize on whitespace and common delimiters
                tokens.extend(
                    t for t in value.replace("|", " | ").replace("=", " = ").split()
                    if len(t) > 0
                )
            elif isinstance(value, (int, float)):
                tokens.append(str(value))

        if len(tokens) <= 1:
            return 0.0  # Single-token or empty → zero entropy

        # Calculate Shannon entropy
        counts = Counter(tokens)
        total = len(tokens)
        entropy = -sum(
            (count / total) * math.log2(count / total)
            for count in counts.values()
            if count > 0
        )

        # Normalize: maximum entropy for N unique tokens is log₂(N)
        max_entropy = math.log2(len(counts))
        if max_entropy == 0:
            return 0.0

        return min(entropy / max_entropy, 1.0)

    def _compute_access_privilege_level(
        self, tool_name: str, tool_args: dict
    ) -> float:
        """Maps the tool and its arguments to a privilege tier.

        Delegates to the pattern library's ``get_privilege_score``
        which applies SPL verb elevation on top of base tool privilege.

        Args:
            tool_name: The MCP tool name.
            tool_args: The tool call arguments.

        Returns:
            Privilege score in [0.0, 1.0].
        """
        return get_privilege_score(tool_name, tool_args)

    def _compute_semantic_deviation(
        self,
        tool_name: str,
        tool_args: dict,
        session_context: FirewallSessionContext,
    ) -> float:
        """Computes cosine distance between this call and the session centroid.

        A sudden spike indicates the agent has deviated from its
        diagnostic trajectory — potentially due to prompt injection
        or tool poisoning altering the LLM's reasoning.

        Uses an embedding cache keyed by argument hash to avoid
        redundant model invocations for repeated argument patterns.

        Args:
            tool_name: The MCP tool name.
            tool_args: The tool call arguments.
            session_context: The session state tracker.

        Returns:
            Deviation score in [0.0, 1.0] where 1.0 = maximum deviation.
        """
        centroid = session_context.get_active_centroid()
        if centroid is None:
            # First call in the session — no baseline to deviate from
            return 0.0

        # Build a semantic representation of this tool call
        semantic_text = f"{tool_name}: {json.dumps(tool_args, default=str)}"

        # Check embedding cache
        cache_key = hashlib.sha256(semantic_text.encode("utf-8")).hexdigest()
        if cache_key in self._embedding_cache:
            current_embedding = self._embedding_cache[cache_key]
        else:
            encoder = _get_encoder()
            current_embedding = encoder.encode(semantic_text)
            self._embedding_cache[cache_key] = current_embedding

        # Cosine similarity: sim = (A · B) / (||A|| × ||B||)
        dot_product = np.dot(current_embedding, centroid)
        norm_current = np.linalg.norm(current_embedding)
        norm_centroid = np.linalg.norm(centroid)

        if norm_current == 0 or norm_centroid == 0:
            return 0.0

        cosine_similarity = dot_product / (norm_current * norm_centroid)
        # Deviation = 1 - similarity (clamped to [0, 1])
        deviation = max(0.0, min(1.0, 1.0 - cosine_similarity))

        return deviation

    def _check_rate_anomaly(
        self, tool_name: str, session_context: FirewallSessionContext
    ) -> float:
        """Detects abnormal call frequency within the sliding window.

        Normalizes the current rate against the configured maximum
        to produce a score in [0, 1]. A score of 1.0 means the
        rate limit has been reached or exceeded.

        Args:
            tool_name: The MCP tool name.
            session_context: The session state tracker.

        Returns:
            Frequency anomaly score in [0.0, 1.0].
        """
        max_calls = self._rate_limits.get("max_calls_per_10s", 8)
        # Get total call rate over the last 10 seconds
        total_rate_10s = session_context.get_total_rate(window_seconds=10.0)
        # Convert to calls-per-10-seconds
        calls_in_window = total_rate_10s * 10.0

        if max_calls <= 0:
            return 0.0

        return min(calls_in_window / max_calls, 1.0)

    def get_embedding_for_centroid(
        self, tool_name: str, tool_args: dict
    ) -> np.ndarray:
        """Computes and returns the embedding for centroid update.

        Called by the proxy after an ALLOWed call to update the
        session's intent centroid.

        Args:
            tool_name: The MCP tool name.
            tool_args: The tool call arguments.

        Returns:
            768-dimensional numpy array.
        """
        semantic_text = f"{tool_name}: {json.dumps(tool_args, default=str)}"
        cache_key = hashlib.sha256(semantic_text.encode("utf-8")).hexdigest()

        if cache_key in self._embedding_cache:
            return self._embedding_cache[cache_key]

        encoder = _get_encoder()
        embedding = encoder.encode(semantic_text)
        self._embedding_cache[cache_key] = embedding
        return embedding
