# tools/k8s_discovery.py
from kubernetes_asyncio import client, config
from langchain_core.tools import tool
from aegisops.tools.logging_tools import get_logs

@tool
async def get_pod_status(namespace: str, service_name: str) -> str:
    """Hits the Kubernetes CoreV1Api to list pods by app label, returning
    restart count, ready state, and container state. Gracefully handles cluster
    connectivity failures and redirects to get_logs as a fallback."""
    if service_name == '*':
        return "Cannot query Kubernetes with '*' as service name. Please specify a distinct service name."

    try:
        # Load local kubeconfig (~/.kube/config configured in Phase 2)
        await config.load_kube_config()
        v1 = client.CoreV1Api()

        try:
            # Query Pods matched by 'app' metadata label
            label_selector = f"app={service_name}"
            pods = await v1.list_namespaced_pod(namespace=namespace, label_selector=label_selector)

            if not pods.items:
                return f"No active pods discovered matching label '{label_selector}' in namespace '{namespace}'."

            pod_reports = []
            for pod in pods.items:
                name = pod.metadata.name
                phase = pod.status.phase
                restarts = 0
                ready_state = "NotReady"

                # Sum restart logs across container runtimes
                if pod.status.container_statuses:
                    for cs in pod.status.container_statuses:
                        restarts += cs.restart_count
                        if cs.ready:
                            ready_state = "Ready"

                pod_reports.append(
                    f"Pod: {name} | Phase: {phase} | Status: {ready_state} | Restarts: {restarts}"
                )
            return "\n".join(pod_reports)
        finally:
            await v1.api_client.close()

    except Exception as e:
        print(f"Kubernetes API connection failure: {str(e)}. Executing fallback logging pipeline...")
        # Graceful fallback to raw directory log parsing
        return get_logs.invoke({"service_name": service_name, "log_level": "error", "k": 3})
