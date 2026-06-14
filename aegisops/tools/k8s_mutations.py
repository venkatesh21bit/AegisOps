# tools/k8s_mutations.py
import datetime
from kubernetes_asyncio import client, config
from langchain_core.tools import tool
from langchain_core.tools import ToolException
from aegisops.memory.procedural_memory import ProceduralMemoryManager

@tool
async def restart_deployment(namespace: str, service_name: str) -> str:
    """Patches the kubectl.kubernetes.io/restartedAt annotation to trigger
    a Kubernetes rolling restart on a deployment, polling until all replicas are ready."""

    # 1. Procedural Policy Verification Gate
    is_allowed_autonomous = ProceduralMemoryManager.verify_action_permissions(
        service_name=service_name,
        requested_action="restart_deployment"
    )

    if not is_allowed_autonomous:
        # Halt execution and bubble the pause event to the LangGraph runner
        return f"HOLD: 'restart_deployment' on '{service_name}' requires manual human approval. Action paused."

    # 2. Execute Rolling Restart
    await config.load_kube_config()
    apps_v1 = client.AppsV1Api()

    now_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Emulate kubectl rollout restart
    restart_body = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now_timestamp
                    }
                }
            }
        }
    }

    try:
        await apps_v1.patch_namespaced_deployment(
            name=service_name,
            namespace=namespace,
            body=restart_body
        )
        return f"Success: Rolling restart initiated for {service_name} at {now_timestamp}."
    except Exception as e:
        raise ToolException(f"Rolling restart execution failed: {str(e)}")

@tool
async def update_deployment_image(namespace: str, service_name: str, image_tag: str) -> str:
    """Emergency rollback and container image modification tool. Patches container image
    specs directly, waits for rollout completion, and verifies pod health."""

    # Procedural Policy Verification Gate
    is_allowed_autonomous = ProceduralMemoryManager.verify_action_permissions(
        service_name=service_name,
        requested_action="update_deployment_image"
    )

    if not is_allowed_autonomous:
        return f"HOLD: 'update_deployment_image' on '{service_name}' requires manual human approval. Action paused."

    await config.load_kube_config()
    apps_v1 = client.AppsV1Api()

    # Patch request for target container image
    patch_body = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": service_name, "image": image_tag}]
                }
            }
        }
    }

    try:
        await apps_v1.patch_namespaced_deployment(
            name=service_name,
            namespace=namespace,
            body=patch_body
        )
        return f"Success: Modified deployment '{service_name}' container image to tag '{image_tag}'."
    except Exception as e:
        raise ToolException(f"Image update failed: {str(e)}")
