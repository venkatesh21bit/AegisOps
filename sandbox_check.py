import asyncio
from kubernetes_asyncio import client, config
import os
import sys

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


async def check_kubernetes_sandbox():
    print("=" * 60)
    print("  KUBERNETES SANDBOX CONNECTIVITY CHECK")
    print("=" * 60)
    try:
        # Load config from default local context (~/.kube/config)
        await config.load_kube_config()
        v1 = client.CoreV1Api()

        print("\n[OK] Kubeconfig loaded successfully")
        print("\nListing pods in 'default' namespace:")
        pods = await v1.list_namespaced_pod(namespace="default")
        for pod in pods.items:
            status = pod.status.phase
            icon = "OK" if status == "Running" else "FAIL"
            print(
                f"  [{icon}] Pod: {pod.metadata.name} | "
                f"Status: {status} | IP: {pod.status.pod_ip}"
            )

        await v1.api_client.close()
        print("\n[OK] Kubernetes connection successfully verified!")
    except Exception as e:
        print(f"\n[FAIL] Kubernetes connection failed: {str(e)}")


def check_local_logs():
    log_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "logs", "payment-service.log"
    )
    print("\n" + "=" * 60)
    print("  MOCK LOG HARNESS CHECK")
    print("=" * 60)
    print(f"\nChecking mock log files at:\n  {log_path}")

    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            last_lines = f.readlines()[-3:]
            print("\nLast 3 generated log entries:")
            for line in last_lines:
                print(f"  > {line.strip()}")
        print("\n[OK] Log harness successfully verified!")
    else:
        print(
            f"\n[FAIL] Error: Log file not found at {log_path}. "
            "Ensure log_generator.py is running."
        )


async def main():
    await check_kubernetes_sandbox()
    check_local_logs()
    print("\n" + "=" * 60)
    print("  ALL CHECKS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
