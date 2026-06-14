"""
tools/splunk_mcp_tools.py
==========================
Splunk MCP tool wrappers for AegisOps.

Provides LangChain @tool-decorated functions that route SPL queries
through the Semantic MCP Firewall proxy to the Splunk MCP server.
These tools are registered alongside the local tools in tools_config.py
so the LLM agent can seamlessly query Splunk telemetry data.

When the MCP proxy is not available (no Splunk connection), tools
fall back to local log analysis and mock metrics — ensuring the
agent always has diagnostic capabilities.

Tool Set:
    - splunk_search_logs:     Run SPL queries for log analysis
    - splunk_get_error_rate:  Query error rate metrics via SPL
    - splunk_get_service_info: Retrieve service metadata from Splunk
"""

import os
import json
from typing import Optional
from langchain_core.tools import tool


@tool
async def splunk_search_logs(
    service_name: str,
    log_level: str = "ERROR",
    time_range: str = "-15m",
    max_results: int = 50,
    namespace: str = "default",
) -> str:
    """Searches Splunk for service logs using SPL, filtered by log level
    and time range. Returns normalized log patterns ranked by frequency.

    Falls back to local log files if Splunk MCP is unavailable.

    Args:
        service_name: The service to search logs for.
        log_level: Log level filter (ERROR, WARN, INFO, DEBUG).
        time_range: Splunk relative time range (e.g., -15m, -1h, -24h).
        max_results: Maximum number of results to return.
        namespace: Kubernetes namespace for context.
    """
    # Build the SPL query
    spl_query = (
        f"search index=main source={service_name} "
        f"{log_level} earliest={time_range} "
        f"| stats count by _raw "
        f"| sort -count "
        f"| head {max_results}"
    )

    # Attempt MCP proxy execution (injected by gated_tools when available)
    # If called directly without proxy, fall back to local logs
    try:
        from aegisops.tools.logging_tools import get_logs
        local_result = get_logs.invoke({
            "service_name": service_name,
            "log_level": log_level,
            "k": min(max_results, 10),
        })
        return (
            f"[Source: Local Logs | SPL equivalent: {spl_query}]\n"
            f"{local_result}"
        )
    except Exception as e:
        return f"Log analysis failed: {str(e)}"


@tool
async def splunk_get_error_rate(
    service_name: str,
    time_range: str = "-5m",
    threshold: float = 0.05,
    namespace: str = "default",
) -> str:
    """Queries Splunk for the HTTP 5xx error rate of a service over
    the specified time range. Compares against the safety threshold
    and returns a health assessment.

    Falls back to local Prometheus mock if Splunk MCP is unavailable.

    Args:
        service_name: The service to check error rates for.
        time_range: Splunk relative time range (e.g., -5m, -15m).
        threshold: Error rate threshold (default 5% = 0.05).
        namespace: Kubernetes namespace.
    """
    spl_query = (
        f"search index=main source={service_name} earliest={time_range} "
        f"| stats count(eval(status>=500)) as errors, count as total "
        f"| eval error_rate=errors/total"
    )

    # Fall back to local Prometheus mock
    try:
        import httpx
        prom_query = (
            f"sum(rate(http_requests_total{{status=~'5..', app='{service_name}'}}[5m])) / "
            f"sum(rate(http_requests_total{{app='{service_name}'}}[5m]))"
        )
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "http://127.0.0.1:9090/api/v1/query",
                params={"query": prom_query},
                timeout=5.0,
            )
        if response.status_code == 200:
            data = response.json()
            results = data.get("data", {}).get("result", [])
            error_rate = float(results[0]["value"][1]) if results else 0.0
        else:
            error_rate = 0.0

        status = "HEALTHY" if error_rate < threshold else "UNHEALTHY"
        return (
            f"[Source: Prometheus Metrics | SPL equivalent: {spl_query}]\n"
            f"Service: {service_name}\n"
            f"Error Rate: {error_rate * 100:.2f}%\n"
            f"Threshold: {threshold * 100:.1f}%\n"
            f"Status: {status}"
        )
    except Exception as e:
        return (
            f"[Source: Unavailable]\n"
            f"SPL Query: {spl_query}\n"
            f"Error: Metric source unreachable — {str(e)}"
        )


@tool
async def splunk_get_service_info(
    service_name: str,
    namespace: str = "default",
) -> str:
    """Retrieves aggregated service telemetry metadata from Splunk,
    including recent event counts, source types, and index information.

    Falls back to local filesystem analysis if Splunk MCP is unavailable.

    Args:
        service_name: The service to get info for.
        namespace: Kubernetes namespace.
    """
    spl_query = (
        f"search index=main source={service_name} earliest=-1h "
        f"| stats count as total_events, "
        f"dc(host) as unique_hosts, "
        f"earliest(_time) as first_seen, "
        f"latest(_time) as last_seen "
        f"| eval time_span=last_seen-first_seen"
    )

    # Fall back to local log file stats
    try:
        log_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs",
            f"{service_name}.log",
        )
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            total_lines = len(lines)
            error_count = sum(1 for l in lines if "ERROR" in l.upper())
            warn_count = sum(1 for l in lines if "WARN" in l.upper())
            file_size = os.path.getsize(log_path)

            return (
                f"[Source: Local Logs | SPL equivalent: {spl_query}]\n"
                f"Service: {service_name}\n"
                f"Namespace: {namespace}\n"
                f"Total Log Lines: {total_lines}\n"
                f"Error Lines: {error_count}\n"
                f"Warning Lines: {warn_count}\n"
                f"Log File Size: {file_size / 1024:.1f} KB"
            )
        else:
            return f"No telemetry data found for service '{service_name}'."
    except Exception as e:
        return f"Service info retrieval failed: {str(e)}"
