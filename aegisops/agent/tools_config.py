# tools_config.py
"""
Tool registry for the AegisOps SRE agent.

Registers both local infrastructure tools and Splunk MCP tool wrappers.
The gated_tool_executor uses tools_by_name for local routing, while
MCP-prefixed tools are intercepted and routed through SecureMCPProxy.
"""

from aegisops.tools.logging_tools import get_logs
from aegisops.tools.k8s_discovery import get_pod_status
from aegisops.tools.k8s_mutations import restart_deployment, update_deployment_image
from aegisops.tools.health_verification import check_service_health
from aegisops.tools.splunk_mcp_tools import (
    splunk_search_logs,
    splunk_get_error_rate,
    splunk_get_service_info,
)
from aegisops.integrations.otel_filter_engine import (
    otel_analyze_log_noise,
    otel_generate_filter_rules,
    otel_apply_filter_configmap,
)
from aegisops.memory.semantic_memory import retrieve_runbook

# Core tool list bound to the LLM agent
# Includes both local tools and Splunk MCP wrappers
tools_list = [
    # ── Local Infrastructure Tools ────────────────
    get_logs,
    get_pod_status,
    restart_deployment,
    update_deployment_image,
    check_service_health,
    
    # ── Semantic Memory (pgvector) ────────────────
    retrieve_runbook,
    
    # ── Splunk MCP Tools (firewall-gated) ─────────
    splunk_search_logs,
    splunk_get_error_rate,
    splunk_get_service_info,
    
    # ── Telemetry Ingestion Purifier (OTel) ────────
    otel_analyze_log_noise,
    otel_generate_filter_rules,
    otel_apply_filter_configmap,
]

# High-speed key-value mapping for the LangGraph tool-routing node
tools_by_name = {tool.name: tool for tool in tools_list}
