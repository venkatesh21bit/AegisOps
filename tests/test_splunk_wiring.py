"""
test_splunk_wiring.py
======================
Tests for the Splunk MCP tool wrappers and HEC shipper.

Validates that Splunk tools build correct SPL queries, fall back
to local data sources gracefully, and the HEC shipper formats
events correctly.

Usage:
    .venv\\Scripts\\python.exe test_splunk_wiring.py
"""

import sys
import os
import json
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


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
#  Test Suite 1: Splunk MCP Tool Wrappers
# ===================================================================

def test_splunk_tool_imports():
    """Tests that all Splunk MCP tools import correctly."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 1. Splunk Tool Imports ==={Colors.RESET}")

    passed = 0
    total = 0

    total += 1
    try:
        from aegisops.tools.splunk_mcp_tools import (
            splunk_search_logs,
            splunk_get_error_rate,
            splunk_get_service_info,
        )
        log_pass("All 3 Splunk tools imported")
        passed += 1
    except Exception as e:
        log_fail(f"Import failed: {e}")

    # Verify tool names
    total += 1
    if (splunk_search_logs.name == "splunk_search_logs"
        and splunk_get_error_rate.name == "splunk_get_error_rate"
        and splunk_get_service_info.name == "splunk_get_service_info"):
        log_pass("Tool names match expected values")
        passed += 1
    else:
        log_fail("Tool name mismatch")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


def test_splunk_search_logs_fallback():
    """Tests that splunk_search_logs falls back to local log files."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 2. Splunk Search Logs Fallback ==={Colors.RESET}")

    from aegisops.tools.splunk_mcp_tools import splunk_search_logs
    passed = 0
    total = 0

    # Check for a test log file
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    test_service = None
    if os.path.exists(log_dir):
        for f in os.listdir(log_dir):
            if f.endswith(".log"):
                test_service = f.replace(".log", "")
                break

    if test_service:
        total += 1
        result = asyncio.run(splunk_search_logs.ainvoke({
            "service_name": test_service,
            "log_level": "ERROR",
            "time_range": "-15m",
        }))
        if "Local Logs" in result and "SPL equivalent" in result:
            log_pass(f"Fallback to local logs for {test_service}")
            passed += 1
        else:
            log_fail(f"Unexpected fallback result: {result[:100]}")
    else:
        print(f"  {Colors.YELLOW}[SKIP] No log files found{Colors.RESET}")

    # Non-existent service should error gracefully
    total += 1
    result = asyncio.run(splunk_search_logs.ainvoke({
        "service_name": "nonexistent-service",
        "log_level": "ERROR",
    }))
    if "not found" in result.lower() or "error" in result.lower() or "Log analysis" in result:
        log_pass("Graceful handling of missing service")
        passed += 1
    else:
        log_fail(f"Should handle missing service: {result[:100]}")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


def test_splunk_service_info():
    """Tests splunk_get_service_info with local fallback."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 3. Splunk Service Info Fallback ==={Colors.RESET}")

    from aegisops.tools.splunk_mcp_tools import splunk_get_service_info
    passed = 0
    total = 0

    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    test_service = None
    if os.path.exists(log_dir):
        for f in os.listdir(log_dir):
            if f.endswith(".log"):
                test_service = f.replace(".log", "")
                break

    if test_service:
        total += 1
        result = asyncio.run(splunk_get_service_info.ainvoke({
            "service_name": test_service,
        }))
        if "Total Log Lines" in result and "Error Lines" in result:
            log_pass(f"Service info for {test_service}", f"{len(result)} chars")
            passed += 1
        else:
            log_fail(f"Unexpected result: {result[:100]}")
    else:
        print(f"  {Colors.YELLOW}[SKIP] No log files found{Colors.RESET}")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


# ===================================================================
#  Test Suite 2: HEC Shipper
# ===================================================================

def test_hec_shipper_mock():
    """Tests the HEC shipper in mock mode (no Splunk connection)."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 4. HEC Shipper (Mock Mode) ==={Colors.RESET}")

    from aegisops.integrations.splunk_hec_shipper import SplunkHECShipper
    passed = 0
    total = 0

    shipper = SplunkHECShipper(hec_token="")  # Empty token = mock mode

    # Test is_configured property
    total += 1
    if not shipper.is_configured:
        log_pass("Mock mode detected (no token)")
        passed += 1
    else:
        log_fail("Should be in mock mode without token")

    # Test ship_event (should succeed in mock mode)
    total += 1
    result = shipper.ship_event(
        {"test": "data"},
        sourcetype="aegisops:test",
    )
    if result is True:
        log_pass("Mock ship_event returns True")
        passed += 1
    else:
        log_fail(f"Mock ship_event returned {result}")

    # Test ship_incident_event
    total += 1
    result = shipper.ship_incident_event(
        incident_id="INC-TEST",
        service_name="payment-service",
        event_type="triggered",
        details={"autonomy_level": "L3"},
    )
    if result is True:
        log_pass("ship_incident_event in mock mode")
        passed += 1
    else:
        log_fail("ship_incident_event failed")

    # Test ship_tool_execution
    total += 1
    result = shipper.ship_tool_execution(
        incident_id="INC-TEST",
        tool_name="get_logs",
        status="Executed",
        latency_seconds=0.42,
        args={"service_name": "payment-service"},
    )
    if result is True:
        log_pass("ship_tool_execution in mock mode")
        passed += 1
    else:
        log_fail("ship_tool_execution failed")

    # Test batch ship
    total += 1
    events = [
        {"tool": "get_logs", "status": "ok"},
        {"tool": "restart", "status": "paused"},
    ]
    shipped = shipper.ship_batch(events, sourcetype="aegisops:test")
    if shipped == 2:
        log_pass(f"Batch shipped {shipped}/2 events")
        passed += 1
    else:
        log_fail(f"Batch shipped {shipped}/2")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


# ===================================================================
#  Test Suite 3: Tools Config Registration
# ===================================================================

def test_tools_registration():
    """Tests that all tools are registered in tools_config."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== 5. Tools Registration ==={Colors.RESET}")

    passed = 0
    total = 0

    total += 1
    try:
        from aegisops.agent.tools_config import tools_list, tools_by_name

        expected_tools = [
            "get_logs", "get_pod_status", "restart_deployment",
            "update_deployment_image", "check_service_health",
            "retrieve_runbook",
            "splunk_search_logs", "splunk_get_error_rate", "splunk_get_service_info",
            "otel_analyze_log_noise", "otel_generate_filter_rules", "otel_apply_filter_configmap",
        ]

        registered = set(tools_by_name.keys())
        missing = [t for t in expected_tools if t not in registered]

        if not missing:
            log_pass(f"All {len(expected_tools)} tools registered ({len(tools_list)} total)")
            passed += 1
        else:
            log_fail(f"Missing tools: {missing}")
    except Exception as e:
        log_fail(f"Import failed: {e}")

    # Check tool count
    total += 1
    if len(tools_list) >= 12:
        log_pass(f"Tool count: {len(tools_list)} (expected >= 12)")
        passed += 1
    else:
        log_fail(f"Tool count: {len(tools_list)} (expected >= 12)")

    print(f"\n  {Colors.BOLD}Results: {passed}/{total}{Colors.RESET}")
    return passed, total


# ===================================================================
#  Main Runner
# ===================================================================

if __name__ == "__main__":
    print(f"{Colors.BOLD}")
    print("=" * 60)
    print("  AEGISOPS SPLUNK MCP WIRING & HEC SHIPPER -- TESTS")
    print("=" * 60)
    print(f"{Colors.RESET}")

    all_passed = 0
    all_total = 0

    for test_fn in [
        test_splunk_tool_imports,
        test_splunk_search_logs_fallback,
        test_splunk_service_info,
        test_hec_shipper_mock,
        test_tools_registration,
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
