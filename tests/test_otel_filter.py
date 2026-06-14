"""
test_otel_filter.py
====================
Unit tests for the AegisOps OpenTelemetry Ingestion Purifier.

Tests the LogPatternAnalyzer, OTelFilterGenerator, and the LangChain
tool interfaces. No infrastructure dependencies.

Usage:
    .venv\\Scripts\\python.exe test_otel_filter.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aegisops.integrations.otel_filter_engine import (
    LogPatternAnalyzer,
    OTelFilterGenerator,
    otel_analyze_log_noise,
    otel_generate_filter_rules,
)


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def log_pass(name, details=""):
    extra = f" -- {details}" if details else ""
    print(f"  {Colors.GREEN}[PASS] {name}{extra}{Colors.RESET}")


def log_fail(name, details=""):
    extra = f" -- {details}" if details else ""
    print(f"  {Colors.RED}[FAIL] {name}{extra}{Colors.RESET}")


# ===================================================================
#  Test Suite 1: Log Pattern Analyzer
# ===================================================================

def test_normalization():
    """Tests that volatile values are correctly normalized."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 1. Log Line Normalization ==={Colors.RESET}")

    analyzer = LogPatternAnalyzer()
    passed = 0
    total = 0

    # Timestamps
    total += 1
    result = analyzer.normalize_line("2026-06-13 14:32:05.123Z Connection failed on port 8080")
    if "[TS]" in result:
        log_pass("Timestamp normalization", f"'{result[:60]}'")
        passed += 1
    else:
        log_fail("Timestamp normalization", f"'{result}'")

    # IP addresses
    total += 1
    result = analyzer.normalize_line("Connection from 192.168.1.100 refused")
    if "[IP]" in result:
        log_pass("IP address normalization", f"'{result}'")
        passed += 1
    else:
        log_fail("IP address normalization", f"'{result}'")

    # UUIDs
    total += 1
    result = analyzer.normalize_line("Request a1b2c3d4-e5f6-7890-abcd-ef1234567890 failed")
    if "[UUID]" in result:
        log_pass("UUID normalization", f"'{result}'")
        passed += 1
    else:
        log_fail("UUID normalization", f"'{result}'")

    # Large numeric IDs
    total += 1
    result = analyzer.normalize_line("Processing order 1234567 for customer 9876543")
    if "[ID]" in result:
        log_pass("Numeric ID normalization", f"'{result}'")
        passed += 1
    else:
        log_fail("Numeric ID normalization", f"'{result}'")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


def test_severity_detection():
    """Tests log severity level detection."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 2. Severity Detection ==={Colors.RESET}")

    analyzer = LogPatternAnalyzer()
    passed = 0
    total = 0

    cases = [
        ("ERROR: Connection refused", 4),
        ("WARN: High latency detected", 3),
        ("FATAL: Out of memory", 5),
        ("INFO: Service started", 2),
        ("DEBUG: Entering function", 1),
        ("Something with no level", 2),
    ]

    for line, expected in cases:
        total += 1
        result = analyzer.detect_severity(line)
        if result == expected:
            log_pass(f"Severity '{line[:40]}' = {result}")
            passed += 1
        else:
            log_fail(f"Severity '{line[:40]}' = {result}, expected {expected}")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


def test_pattern_analysis():
    """Tests full pattern analysis with noise/signal classification."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 3. Pattern Analysis ==={Colors.RESET}")

    analyzer = LogPatternAnalyzer(noise_threshold=5)
    passed = 0
    total = 0

    # Generate test log lines
    lines = []
    # Noise: 20 identical INFO lines
    for _ in range(20):
        lines.append("2026-06-13 14:00:00 INFO Heartbeat check OK from 10.0.0.1")
    # Noise: 15 identical DEBUG lines
    for _ in range(15):
        lines.append("2026-06-13 14:00:01 DEBUG Processing request 12345")
    # Signal: 3 unique ERROR lines
    lines.append("2026-06-13 14:01:00 ERROR Connection to database failed: timeout after 30s")
    lines.append("2026-06-13 14:01:01 ERROR OOM Kill detected on container payment-worker")
    lines.append("2026-06-13 14:01:02 ERROR FATAL: Segfault in libssl.so.1.1")

    analysis = analyzer.analyze_patterns(lines)
    stats = analysis["stats"]

    # Test: noise patterns identified
    total += 1
    if len(analysis["noise_patterns"]) >= 2:
        log_pass(f"Noise patterns identified: {len(analysis['noise_patterns'])}")
        passed += 1
    else:
        log_fail(f"Expected >= 2 noise patterns, got {len(analysis['noise_patterns'])}")

    # Test: ERROR lines are in signal, not noise
    total += 1
    noise_texts = " ".join(p["pattern"] for p in analysis["noise_patterns"])
    if "ERROR" not in noise_texts and "FATAL" not in noise_texts:
        log_pass("ERROR/FATAL preserved in signal patterns")
        passed += 1
    else:
        log_fail("ERROR/FATAL found in noise patterns!")

    # Test: compression ratio > 50%
    total += 1
    if stats["compression_ratio_pct"] > 50:
        log_pass(f"Compression ratio: {stats['compression_ratio_pct']}%")
        passed += 1
    else:
        log_fail(f"Compression ratio too low: {stats['compression_ratio_pct']}%")

    # Test: total lines counted correctly
    total += 1
    if stats["total_lines"] == len(lines):
        log_pass(f"Total lines: {stats['total_lines']}")
        passed += 1
    else:
        log_fail(f"Total lines: {stats['total_lines']}, expected {len(lines)}")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


# ===================================================================
#  Test Suite 2: OTel Filter Config Generator
# ===================================================================

def test_yaml_generation():
    """Tests OTel Collector YAML config generation."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 4. YAML Config Generation ==={Colors.RESET}")

    analyzer = LogPatternAnalyzer(noise_threshold=3)
    passed = 0
    total = 0

    lines = []
    for _ in range(10):
        lines.append("INFO Heartbeat OK")
    for _ in range(8):
        lines.append("DEBUG Cache miss for key abc123")
    lines.append("ERROR Critical failure in payment-service")

    analysis = analyzer.analyze_patterns(lines)
    yaml_config = OTelFilterGenerator.generate_filter_config(
        analysis, "payment-service", "INC-TEST-001"
    )

    # Test: YAML contains processor definition
    total += 1
    if "processors:" in yaml_config:
        log_pass("Contains 'processors:' section")
        passed += 1
    else:
        log_fail("Missing 'processors:' section")

    # Test: Contains filter definition
    total += 1
    if "filter/aegisops_dynamic:" in yaml_config:
        log_pass("Contains filter/aegisops_dynamic processor")
        passed += 1
    else:
        log_fail("Missing filter/aegisops_dynamic processor")

    # Test: Contains transform definition
    total += 1
    if "transform/aegisops_noise_suppression:" in yaml_config:
        log_pass("Contains transform/aegisops_noise_suppression")
        passed += 1
    else:
        log_fail("Missing transform/aegisops_noise_suppression")

    # Test: Contains incident ID
    total += 1
    if "INC-TEST-001" in yaml_config:
        log_pass("Contains incident ID")
        passed += 1
    else:
        log_fail("Missing incident ID in YAML")

    # Test: Contains rate limiter
    total += 1
    if "probabilistic_sampler" in yaml_config:
        log_pass("Contains probabilistic sampler rate limiter")
        passed += 1
    else:
        log_fail("Missing rate limiter")

    # Test: Contains splunk_hec exporter
    total += 1
    if "splunk_hec" in yaml_config:
        log_pass("Contains splunk_hec exporter reference")
        passed += 1
    else:
        log_fail("Missing splunk_hec exporter")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


def test_cost_estimation():
    """Tests the cost savings estimation."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 5. Cost Estimation ==={Colors.RESET}")

    analyzer = LogPatternAnalyzer(noise_threshold=3)
    passed = 0
    total = 0

    lines = []
    for _ in range(100):
        lines.append("INFO Heartbeat OK")
    for _ in range(50):
        lines.append("DEBUG Request processed in 12ms")
    for _ in range(5):
        lines.append("ERROR Database connection pool exhausted")

    analysis = analyzer.analyze_patterns(lines)
    cost_report = OTelFilterGenerator.generate_cost_report(analysis, "payment-service")

    # Test: compression ratio is reasonable
    total += 1
    if 80 < cost_report["compression_ratio_pct"] <= 100:
        log_pass(f"Compression ratio: {cost_report['compression_ratio_pct']}%")
        passed += 1
    else:
        log_fail(f"Compression ratio: {cost_report['compression_ratio_pct']}%")

    # Test: monthly savings calculated
    total += 1
    if cost_report["projected_monthly_savings_gb"] > 0:
        log_pass(f"Monthly savings: {cost_report['projected_monthly_savings_gb']} GB")
        passed += 1
    else:
        log_fail(f"No monthly savings projected")

    # Test: cost savings in USD
    total += 1
    if cost_report["estimated_monthly_cost_savings_usd"] > 0:
        log_pass(f"Cost savings: ${cost_report['estimated_monthly_cost_savings_usd']}")
        passed += 1
    else:
        log_fail(f"No cost savings estimated")

    # Test: signal patterns preserved (ERROR lines)
    total += 1
    if cost_report["signal_patterns_preserved"] >= 1:
        log_pass(f"Signal patterns preserved: {cost_report['signal_patterns_preserved']}")
        passed += 1
    else:
        log_fail(f"No signal patterns preserved!")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


# ===================================================================
#  Test Suite 3: LangChain Tool Integration
# ===================================================================

def test_tool_execution():
    """Tests that the LangChain tools execute correctly against local logs."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 6. LangChain Tool Execution ==={Colors.RESET}")

    passed = 0
    total = 0

    # Check if a test log file exists
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    test_service = None

    if os.path.exists(log_dir):
        for f in os.listdir(log_dir):
            if f.endswith(".log"):
                test_service = f.replace(".log", "")
                break

    if test_service:
        # Test otel_analyze_log_noise
        total += 1
        result = otel_analyze_log_noise.invoke({
            "service_name": test_service,
            "noise_threshold": 3,
        })
        if "Log Noise Analysis" in result and "Total Lines" in result:
            log_pass(f"otel_analyze_log_noise ({test_service})", f"{len(result)} chars")
            passed += 1
        else:
            log_fail(f"otel_analyze_log_noise output unexpected: {result[:100]}")

        # Test otel_generate_filter_rules
        total += 1
        result = otel_generate_filter_rules.invoke({
            "service_name": test_service,
            "incident_id": "INC-TEST-OTEL",
            "noise_threshold": 3,
        })
        if "OTel Filter Rules" in result and "processors:" in result:
            log_pass(f"otel_generate_filter_rules ({test_service})", f"{len(result)} chars")
            passed += 1
        else:
            log_fail(f"otel_generate_filter_rules output unexpected: {result[:100]}")
    else:
        print(f"  {Colors.YELLOW}[SKIP] No log files found in logs/ directory{Colors.RESET}")

    # Test with non-existent service (should handle gracefully)
    total += 1
    result = otel_analyze_log_noise.invoke({
        "service_name": "nonexistent-service",
        "noise_threshold": 5,
    })
    if "No log file" in result or "Cannot analyze" in result:
        log_pass("Graceful handling of missing log file")
        passed += 1
    else:
        log_fail(f"Should handle missing log gracefully: {result[:100]}")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


def test_configmap_generation():
    """Tests the Kubernetes ConfigMap YAML generation."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 7. ConfigMap Generation ==={Colors.RESET}")

    passed = 0
    total = 0

    # Check for test log
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    test_service = None
    if os.path.exists(log_dir):
        for f in os.listdir(log_dir):
            if f.endswith(".log"):
                test_service = f.replace(".log", "")
                break

    if test_service:
        from aegisops.integrations.otel_filter_engine import otel_apply_filter_configmap
        total += 1
        result = otel_apply_filter_configmap.invoke({
            "service_name": test_service,
            "incident_id": "INC-TEST-CM",
            "noise_threshold": 3,
        })
        if "apiVersion: v1" in result and "kind: ConfigMap" in result:
            log_pass("Valid Kubernetes ConfigMap YAML")
            passed += 1
        else:
            log_fail(f"Invalid ConfigMap: {result[:100]}")

        total += 1
        if "aegisops.io/incident" in result:
            log_pass("ConfigMap has aegisops labels")
            passed += 1
        else:
            log_fail("ConfigMap missing aegisops labels")
    else:
        print(f"  {Colors.YELLOW}[SKIP] No log files found{Colors.RESET}")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


# ===================================================================
#  Main Runner
# ===================================================================

if __name__ == "__main__":
    print(f"{Colors.BOLD}")
    print("=" * 60)
    print("  AEGISOPS OPENTELEMETRY INGESTION PURIFIER -- TESTS")
    print("=" * 60)
    print(f"{Colors.RESET}")

    all_passed = 0
    all_total = 0

    for test_fn in [
        test_normalization,
        test_severity_detection,
        test_pattern_analysis,
        test_yaml_generation,
        test_cost_estimation,
        test_tool_execution,
        test_configmap_generation,
    ]:
        p, t = test_fn()
        all_passed += p
        all_total += t

    print(f"\n{Colors.BOLD}")
    print("=" * 60)
    if all_passed == all_total:
        print(f"  {Colors.GREEN}ALL {all_total} TESTS PASSED [OK]{Colors.RESET}")
    else:
        failed = all_total - all_passed
        print(f"  {Colors.RED}{all_passed}/{all_total} PASSED -- {failed} FAILURES{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")

    sys.exit(0 if all_passed == all_total else 1)
