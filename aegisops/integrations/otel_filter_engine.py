"""
otel_filter_engine.py
======================
OpenTelemetry Collector Filter Rule Generator for AegisOps.

Dynamically generates OTel Collector processor configurations that
suppress high-cardinality, duplicate, or noisy log/trace/metric
streams during active incidents. This serves as a cost-control
mechanism that reduces Splunk ingestion volume by filtering at the
collector layer rather than dropping events post-ingestion.

Architecture:
    Error Storm Detected
         │
         ▼
    otel_generate_filter_rules()
         │
         ├──► Analyze log patterns (frequency + entropy)
         ├──► Classify noise vs. signal (severity + uniqueness)
         ├──► Build OTel filter_processor YAML config
         └──► Return deployable config + estimated savings

    OTel Collector
         │
         ├──► filter/aegisops_dynamic:
         │       └──► Drop duplicate log patterns
         │       └──► Rate-limit high-frequency sources
         │       └──► Preserve ERROR/FATAL signals
         └──► exporters/splunk_hec: (cleaned data only)

Integration:
    The generated YAML can be:
    1. Applied to a running OTel Collector via ConfigMap update + rollout
    2. Used as a reference for manual operator review
    3. Fed back to the LLM agent as context for cost-aware decisions
"""

import os
import re
import math
import json
import time
import hashlib
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from langchain_core.tools import tool


# ═══════════════════════════════════════════════════════════════════════
#  Pattern Analysis Engine
# ═══════════════════════════════════════════════════════════════════════

class LogPatternAnalyzer:
    """Analyzes log streams to identify noise patterns suitable for
    OTel collector-level filtering.

    Classifies log lines into signal (unique, actionable errors) and
    noise (repetitive, high-cardinality duplicates) using a combination
    of normalization, frequency analysis, and entropy scoring.
    """

    # Volatile elements to normalize before pattern grouping
    _NORMALIZERS = [
        (re.compile(r'\d{4}-\d{2}-\d{2}\s*\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?'), '[TS]'),
        (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[IP]'),
        (re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), '[UUID]'),
        (re.compile(r'\b\d{5,}\b'), '[ID]'),
        (re.compile(r'port\s*\d+', re.IGNORECASE), 'port [PORT]'),
        (re.compile(r'(?:latency|duration|elapsed|took)\s*[=:]\s*\d+(?:\.\d+)?\s*(?:ms|s)', re.IGNORECASE), '[LATENCY]'),
    ]

    # Severity classification for log-level detection
    _SEVERITY_LEVELS = {
        "FATAL": 5, "CRITICAL": 5,
        "ERROR": 4, "ERR": 4,
        "WARN": 3, "WARNING": 3,
        "INFO": 2,
        "DEBUG": 1, "TRACE": 1,
    }

    def __init__(self, noise_threshold: int = 10, preserve_severity: int = 4):
        """
        Args:
            noise_threshold: Minimum occurrences for a pattern to be
                considered noise (default: 10 repetitions).
            preserve_severity: Minimum severity level to always preserve
                (default: 4 = ERROR+). Never filter ERROR/FATAL.
        """
        self.noise_threshold = noise_threshold
        self.preserve_severity = preserve_severity

    def normalize_line(self, line: str) -> str:
        """Normalizes volatile values in a log line for pattern grouping."""
        normalized = line.strip()
        for pattern, replacement in self._NORMALIZERS:
            normalized = pattern.sub(replacement, normalized)
        return normalized

    def detect_severity(self, line: str) -> int:
        """Detects the severity level of a log line.

        Returns:
            Integer severity (1=DEBUG to 5=FATAL), or 2 (INFO) if unknown.
        """
        upper = line.upper()
        for keyword, level in self._SEVERITY_LEVELS.items():
            if keyword in upper:
                return level
        return 2  # Default to INFO

    def analyze_patterns(
        self, lines: List[str]
    ) -> Dict[str, Any]:
        """Performs full pattern analysis on a log stream.

        Returns:
            Dictionary containing:
                - noise_patterns: High-frequency patterns safe to filter
                - signal_patterns: Low-frequency or high-severity patterns to preserve
                - stats: Aggregate statistics for cost estimation
        """
        normalized_lines = []
        severity_map: Dict[str, int] = {}

        for line in lines:
            if not line.strip():
                continue
            normalized = self.normalize_line(line)
            severity = self.detect_severity(line)
            normalized_lines.append(normalized)
            # Track max severity seen for each normalized pattern
            if normalized not in severity_map or severity > severity_map[normalized]:
                severity_map[normalized] = severity

        # Count pattern frequencies
        counter = Counter(normalized_lines)
        total_lines = len(normalized_lines)

        noise_patterns: List[Dict[str, Any]] = []
        signal_patterns: List[Dict[str, Any]] = []

        for pattern, count in counter.most_common():
            severity = severity_map.get(pattern, 2)
            entry = {
                "pattern": pattern[:200],  # Truncate for display
                "count": count,
                "frequency_pct": round((count / total_lines) * 100, 1) if total_lines > 0 else 0,
                "severity": severity,
                "fingerprint": hashlib.md5(pattern.encode()).hexdigest()[:12],
            }

            # Never filter ERROR/FATAL; only filter high-frequency noise
            if severity < self.preserve_severity and count >= self.noise_threshold:
                noise_patterns.append(entry)
            else:
                signal_patterns.append(entry)

        # Calculate compression ratio (how much data can be filtered)
        noise_line_count = sum(p["count"] for p in noise_patterns)
        compression_ratio = (noise_line_count / total_lines * 100) if total_lines > 0 else 0

        return {
            "noise_patterns": noise_patterns,
            "signal_patterns": signal_patterns[:20],  # Top 20 signals
            "stats": {
                "total_lines": total_lines,
                "unique_patterns": len(counter),
                "noise_patterns_count": len(noise_patterns),
                "signal_patterns_count": len(signal_patterns),
                "filterable_lines": noise_line_count,
                "compression_ratio_pct": round(compression_ratio, 1),
            },
        }


# ═══════════════════════════════════════════════════════════════════════
#  OTel Filter Configuration Generator
# ═══════════════════════════════════════════════════════════════════════

class OTelFilterGenerator:
    """Generates OpenTelemetry Collector filter processor configurations.

    Produces YAML-compatible configuration blocks that can be injected
    into a running OTel Collector's processor pipeline to dynamically
    suppress noise patterns identified during incident analysis.
    """

    @staticmethod
    def generate_filter_config(
        analysis: Dict[str, Any],
        service_name: str,
        incident_id: str,
    ) -> str:
        """Generates an OTel Collector filter processor YAML config.

        Args:
            analysis: The pattern analysis result from LogPatternAnalyzer.
            service_name: The service being filtered.
            incident_id: The incident context for traceability.

        Returns:
            YAML configuration string for the OTel Collector.
        """
        noise_patterns = analysis.get("noise_patterns", [])
        stats = analysis.get("stats", {})

        # Build regex patterns for the filter processor
        filter_regexes = []
        for noise in noise_patterns[:25]:  # Cap at 25 rules
            # Escape special regex chars in the fingerprinted pattern
            escaped = re.escape(noise["pattern"][:100])
            # Replace normalized placeholders with broad matchers
            escaped = escaped.replace(re.escape("[TS]"), r".*")
            escaped = escaped.replace(re.escape("[IP]"), r"\d+\.\d+\.\d+\.\d+")
            escaped = escaped.replace(re.escape("[UUID]"), r"[0-9a-f-]{36}")
            escaped = escaped.replace(re.escape("[ID]"), r"\d+")
            escaped = escaped.replace(re.escape("[PORT]"), r"\d+")
            escaped = escaped.replace(re.escape("[LATENCY]"), r".*")
            filter_regexes.append(escaped)

        # Format as OTel Collector YAML
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        indent = "        "

        yaml_lines = [
            f"# AegisOps Dynamic Filter Configuration",
            f"# Generated: {timestamp}",
            f"# Incident:  {incident_id}",
            f"# Service:   {service_name}",
            f"# Estimated noise reduction: {stats.get('compression_ratio_pct', 0)}%",
            f"# Filterable lines: {stats.get('filterable_lines', 0)} / {stats.get('total_lines', 0)}",
            f"",
            f"processors:",
            f"  filter/aegisops_dynamic:",
            f"    logs:",
            f"      log_record:",
            f"        - 'severity_number < 9'  # Preserve WARN and above",
        ]

        if filter_regexes:
            yaml_lines.append(f"")
            yaml_lines.append(f"  transform/aegisops_noise_suppression:")
            yaml_lines.append(f"    log_statements:")
            yaml_lines.append(f"      - context: log")
            yaml_lines.append(f"        conditions:")

            for i, regex in enumerate(filter_regexes[:15]):
                yaml_lines.append(
                    f"          - 'body != nil and IsMatch(body, \"{regex}\")'"
                )

            yaml_lines.append(f"        statements:")
            yaml_lines.append(f"          - 'set(attributes[\"aegisops.filtered\"], true)'")
            yaml_lines.append(f"          - 'set(attributes[\"aegisops.incident_id\"], \"{incident_id}\")'")

        # Add rate limiter for high-cardinality sources
        yaml_lines.extend([
            f"",
            f"  # Rate limiter: cap throughput during error storms",
            f"  probabilistic_sampler/aegisops_rate_limit:",
            f"    sampling_percentage: 25  # Sample 25% during storms",
            f"",
            f"service:",
            f"  pipelines:",
            f"    logs:",
            f"      receivers: [otlp]",
            f"      processors:",
            f"        - filter/aegisops_dynamic",
            f"        - transform/aegisops_noise_suppression",
            f"        - probabilistic_sampler/aegisops_rate_limit",
            f"        - batch",
            f"      exporters: [splunk_hec/logs]",
        ])

        return "\n".join(yaml_lines)

    @staticmethod
    def generate_cost_report(
        analysis: Dict[str, Any],
        service_name: str,
        avg_bytes_per_line: int = 250,
        cost_per_gb: float = 15.0,
    ) -> Dict[str, Any]:
        """Estimates the cost savings from applying the filter rules.

        Args:
            analysis: Pattern analysis result.
            service_name: The service being analyzed.
            avg_bytes_per_line: Average bytes per log line.
            cost_per_gb: Splunk ingestion cost per GB per day.

        Returns:
            Cost analysis dictionary with daily/monthly projections.
        """
        stats = analysis.get("stats", {})
        filterable = stats.get("filterable_lines", 0)
        total = stats.get("total_lines", 0)

        # Project from sample window to daily volume
        # Assume the sample represents 15 minutes of data
        daily_multiplier = (24 * 60) / 15
        daily_filterable_bytes = filterable * avg_bytes_per_line * daily_multiplier
        daily_total_bytes = total * avg_bytes_per_line * daily_multiplier

        daily_savings_gb = daily_filterable_bytes / (1024 ** 3)
        monthly_savings_gb = daily_savings_gb * 30
        monthly_cost_savings = monthly_savings_gb * cost_per_gb

        return {
            "service_name": service_name,
            "sample_lines_analyzed": total,
            "filterable_lines_in_sample": filterable,
            "compression_ratio_pct": stats.get("compression_ratio_pct", 0),
            "projected_daily_savings_gb": round(daily_savings_gb, 2),
            "projected_monthly_savings_gb": round(monthly_savings_gb, 2),
            "estimated_monthly_cost_savings_usd": round(monthly_cost_savings, 2),
            "noise_patterns_identified": stats.get("noise_patterns_count", 0),
            "signal_patterns_preserved": stats.get("signal_patterns_count", 0),
        }


# ═══════════════════════════════════════════════════════════════════════
#  LangChain Tool Interfaces
# ═══════════════════════════════════════════════════════════════════════

@tool
def otel_analyze_log_noise(
    service_name: str,
    noise_threshold: int = 10,
    namespace: str = "default",
) -> str:
    """Analyzes a service's log stream to identify noise patterns suitable
    for OpenTelemetry collector-level filtering. Returns the top noise
    patterns, signal patterns, and compression statistics.

    Use this tool to understand what percentage of logs are repetitive
    noise vs. actionable signals before generating filter rules.

    Args:
        service_name: The service to analyze logs for.
        noise_threshold: Minimum occurrences for a pattern to be noise.
        namespace: Kubernetes namespace context.
    """
    log_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "logs",
        f"{service_name}.log",
    )

    try:
        if not os.path.exists(log_path):
            return f"No log file found at {log_path}. Cannot analyze patterns."

        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]

        analyzer = LogPatternAnalyzer(noise_threshold=noise_threshold)
        analysis = analyzer.analyze_patterns(lines)
        stats = analysis["stats"]

        output = [
            f"═══ Log Noise Analysis for {service_name} ═══",
            f"Total Lines Analyzed: {stats['total_lines']}",
            f"Unique Patterns:      {stats['unique_patterns']}",
            f"Noise Patterns:       {stats['noise_patterns_count']}",
            f"Signal Patterns:      {stats['signal_patterns_count']}",
            f"Compression Ratio:    {stats['compression_ratio_pct']}%",
            f"Filterable Lines:     {stats['filterable_lines']} / {stats['total_lines']}",
            "",
        ]

        if analysis["noise_patterns"]:
            output.append("── Top Noise Patterns (safe to filter) ──")
            for noise in analysis["noise_patterns"][:5]:
                output.append(
                    f"  [{noise['count']}x | {noise['frequency_pct']}%] "
                    f"{noise['pattern'][:120]}"
                )
            output.append("")

        if analysis["signal_patterns"]:
            output.append("── Signal Patterns (preserved) ──")
            for sig in analysis["signal_patterns"][:5]:
                severity_label = {5: "FATAL", 4: "ERROR", 3: "WARN", 2: "INFO", 1: "DEBUG"}.get(
                    sig["severity"], "UNKNOWN"
                )
                output.append(
                    f"  [{sig['count']}x | {severity_label}] "
                    f"{sig['pattern'][:120]}"
                )

        return "\n".join(output)

    except Exception as e:
        return f"Log noise analysis failed: {str(e)}"


@tool
def otel_generate_filter_rules(
    service_name: str,
    incident_id: str = "INC-AUTO",
    noise_threshold: int = 10,
    namespace: str = "default",
) -> str:
    """Generates OpenTelemetry Collector filter processor configuration
    to suppress identified noise patterns for a service. Returns a
    deployable YAML configuration block plus cost savings estimates.

    Use this tool after confirming noise patterns with otel_analyze_log_noise.
    The generated config can be applied to the OTel Collector ConfigMap.

    Args:
        service_name: The service to generate filters for.
        incident_id: The incident context for traceability.
        noise_threshold: Minimum occurrences for noise classification.
        namespace: Kubernetes namespace context.
    """
    log_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "logs",
        f"{service_name}.log",
    )

    try:
        if not os.path.exists(log_path):
            return f"No log file found for {service_name}. Cannot generate filter rules."

        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]

        analyzer = LogPatternAnalyzer(noise_threshold=noise_threshold)
        analysis = analyzer.analyze_patterns(lines)

        generator = OTelFilterGenerator()
        yaml_config = generator.generate_filter_config(
            analysis, service_name, incident_id
        )
        cost_report = generator.generate_cost_report(analysis, service_name)

        output = [
            f"═══ OTel Filter Rules Generated for {service_name} ═══",
            f"Incident: {incident_id}",
            f"",
            f"── Cost Impact Estimate ──",
            f"Compression Ratio:     {cost_report['compression_ratio_pct']}%",
            f"Daily Savings:         {cost_report['projected_daily_savings_gb']} GB",
            f"Monthly Savings:       {cost_report['projected_monthly_savings_gb']} GB",
            f"Est. Monthly Cost:     ${cost_report['estimated_monthly_cost_savings_usd']}",
            f"Noise Patterns Found:  {cost_report['noise_patterns_identified']}",
            f"Signals Preserved:     {cost_report['signal_patterns_preserved']}",
            f"",
            f"── Deployable OTel Collector Configuration ──",
            yaml_config,
        ]

        return "\n".join(output)

    except Exception as e:
        return f"Filter rule generation failed: {str(e)}"


@tool
def otel_apply_filter_configmap(
    service_name: str,
    incident_id: str = "INC-AUTO",
    noise_threshold: int = 10,
    namespace: str = "default",
) -> str:
    """Generates and stages an OTel Collector ConfigMap update with
    the dynamic noise filter rules. In production, this would apply
    the ConfigMap and trigger a rolling restart of the OTel DaemonSet.

    CAUTION: This is a mutating action that affects log ingestion.
    It will be gated by the procedural policy engine.

    Args:
        service_name: The service to filter.
        incident_id: Incident context for traceability.
        noise_threshold: Noise classification threshold.
        namespace: Target namespace for the ConfigMap.
    """
    log_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "logs",
        f"{service_name}.log",
    )

    try:
        if not os.path.exists(log_path):
            return f"No log data available for {service_name}. Cannot generate ConfigMap."

        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]

        analyzer = LogPatternAnalyzer(noise_threshold=noise_threshold)
        analysis = analyzer.analyze_patterns(lines)
        stats = analysis["stats"]

        # Generate the config
        generator = OTelFilterGenerator()
        yaml_config = generator.generate_filter_config(
            analysis, service_name, incident_id
        )

        # Stage the ConfigMap YAML
        configmap_yaml = f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: otel-collector-aegisops-filter
  namespace: {namespace}
  labels:
    app: otel-collector
    aegisops.io/incident: "{incident_id}"
    aegisops.io/managed-by: "aegisops-agent"
data:
  dynamic_filter.yaml: |
{_indent_yaml(yaml_config, 4)}
"""

        return (
            f"ConfigMap staged for OTel Collector filter update.\n"
            f"Incident: {incident_id}\n"
            f"Service: {service_name}\n"
            f"Noise patterns to suppress: {stats.get('noise_patterns_count', 0)}\n"
            f"Expected compression: {stats.get('compression_ratio_pct', 0)}%\n"
            f"\n"
            f"── Kubernetes ConfigMap ──\n"
            f"{configmap_yaml}\n"
            f"\n"
            f"To apply: kubectl apply -f <configmap> && "
            f"kubectl rollout restart daemonset/otel-collector -n {namespace}"
        )

    except Exception as e:
        return f"ConfigMap generation failed: {str(e)}"


def _indent_yaml(text: str, spaces: int) -> str:
    """Indents every line of text by the specified number of spaces."""
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.split("\n"))
