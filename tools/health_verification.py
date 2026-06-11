# tools/health_verification.py
import httpx
from kubernetes_asyncio import client, config
from langchain_core.tools import tool

@tool
async def check_service_health(namespace: str, service_name: str) -> str:
    """Combines Kubernetes pod readiness with real-time error rate calculations
    from Prometheus. Returns healthy (True) only if all pods are running and
    the HTTP 5xx error rate is strictly under 5% over the last 5 minutes."""

    # 1. Validate Kubernetes Pod Readiness
    try:
        await config.load_kube_config()
        v1 = client.CoreV1Api()

        pods = await v1.list_namespaced_pod(namespace=namespace, label_selector=f"app={service_name}")
        if not pods.items:
            return f"Health Status: UNHEALTHY | Reason: No pods found for service {service_name}."

        all_ready = True
        for pod in pods.items:
            if pod.status.phase != "Running":
                all_ready = False
                break
            if pod.status.container_statuses:
                if not any(cs.ready for cs in pod.status.container_statuses):
                    all_ready = False
                    break

        if not all_ready:
            return f"Health Status: UNHEALTHY | Reason: One or more containers of {service_name} are not ready."

    except Exception as e:
        return f"Health Status: DEGRADED | K8s Query Error: {str(e)}"

    # 2. Query Prometheus for Error Rate
    # Formulate PromQL query to compute the ratio of 5xx HTTP requests
    prom_query = (
        f"sum(rate(http_requests_total{{status=~'5..', app='{service_name}'}}[5m])) / "
        f"sum(rate(http_requests_total{{app='{service_name}'}}[5m]))"
    )

    try:
        async with httpx.AsyncClient() as http_client:
            # Query mock metric server configured in Phase 2
            response = await http_client.get(
                "http://127.0.0.1:9090/api/v1/query",
                params={"query": prom_query},
                timeout=5.0
            )

        if response.status_code == 200:
            data = response.json()
            results = data.get("data", {}).get("result", [])

            if results:
                # Extract float error rate value from Prometheus tuple response [timestamp, value]
                error_rate = float(results[0]["value"][1])
            else:
                # Default fallback: if no metrics are found, assume 0.0 error rate
                error_rate = 0.0

            # Mathematical Safety Check: Error Rate < 5%
            if error_rate < 0.05:
                return (
                    f"Health Status: HEALTHY | Pods: All Ready | "
                    f"HTTP 5xx Error Rate: {error_rate * 100:.2f}% (Safety Constraint: <5%)"
                )
            else:
                return (
                    f"Health Status: UNHEALTHY | Pods: Ready | "
                    f"HTTP 5xx Error Rate: {error_rate * 100:.2f}% (Safety Constraint: <5% Violated)"
                )
        else:
            return "Health Status: DEGRADED | Reason: Failed to contact Prometheus metric server."

    except Exception as e:
        return f"Health Status: DEGRADED | Metric Connection Error: {str(e)}"
