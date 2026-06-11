# tools_config.py
from tools.logging_tools import get_logs
from tools.k8s_discovery import get_pod_status
from tools.k8s_mutations import restart_deployment, update_deployment_image
from tools.health_verification import check_service_health
from semantic_memory import retrieve_runbook  # Exported in Phase 4

# Core tool list bound to the LLM agent
tools_list = [
    get_logs,
    get_pod_status,
    restart_deployment,
    update_deployment_image,
    check_service_health,
    retrieve_runbook
]

# High-speed key-value mapping for the LangGraph tool-routing node
tools_by_name = {tool.name: tool for tool in tools_list}
