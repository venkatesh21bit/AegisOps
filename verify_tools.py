# verify_tools.py
import sys
import asyncio
import os

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from tools_config import tools_by_name
from procedural_memory import ProceduralMemoryManager

async def run_verification():
    print("=" * 60)
    print("  AEGISOPS PHASE 6: TACTICAL TOOL VERIFICATION")
    print("=" * 60)

    print("\nInitializing Procedural Policy Rules...")
    # Seed safe defaults to Redis
    ProceduralMemoryManager.load_policies_to_cache()

    print("\n--- 1. Testing get_logs normalization ---")
    log_test = tools_by_name["get_logs"].invoke({
        "service_name": "payment-service",
        "log_level": "error",
        "k": 2
    })
    print(log_test)

    print("\n--- 2. Testing get_pod_status with K8s Fallback ---")
    pod_test = await tools_by_name["get_pod_status"].ainvoke({
        "namespace": "default",
        "service_name": "payment-service"
    })
    print(pod_test)

    print("\n--- 3. Testing check_service_health (Prometheus + K8s) ---")
    health_test = await tools_by_name["check_service_health"].ainvoke({
        "namespace": "default",
        "service_name": "payment-service"
    })
    print(health_test)

    print("\n--- 4. Testing Mutating Tool (restart_deployment - Blocked without Approval) ---")
    # restart_deployment should evaluate payment-service policies inside Redis
    restart_test = await tools_by_name["restart_deployment"].ainvoke({
        "namespace": "default",
        "service_name": "payment-service"
    })
    print(restart_test)  # Expected: HOLD output (approval required)

    print("\n--- 5. Testing retrieve_runbook (Semantic Memory RAG) ---")
    runbook_test = tools_by_name["retrieve_runbook"].invoke({
        "query": "payment-service latency failure"
    })
    print(runbook_test)

    print("\n" + "=" * 60)
    print("  ALL TOOL VERIFICATIONS COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_verification())
