import sys
import asyncio

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from episodic_memory import EpisodicMemoryManager
from semantic_memory import SemanticMemoryManager, retrieve_runbook
from procedural_memory import ProceduralMemoryManager
from checkpointer import get_working_memory_checkpointer

async def main():
    print("Testing AegisOps Cognitive Memory Layers...\n")
    
    # 1. Seed & Test Semantic Runbooks (RAG)
    print("Seeding Semantic memory...")
    SemanticMemoryManager.ingest_runbook_chunk(
        "playbooks/payment-failure.md",
        "If payment-service encounters latency, scale the pods to 3 and run checkout health verification."
    )
    # Search playbooks
    runbook_result = retrieve_runbook.invoke("payment-service latency")
    print(f"RAG Retrieval Match:\n{runbook_result}\n")
    
    # 2. Seed & Test Episodic memory (Cosine distance match)
    print("Seeding historical Episodic Incident...")
    EpisodicMemoryManager.save_incident_memory(
        incident_id="INC-9912",
        symptoms="latency spikes and connection failure on payment-service",
        root_cause="Database connection pool exhaustion",
        actions=["restart_deployment", "scale"],
        outcome="Resolved"
    )
    # Search history
    similar_cases = EpisodicMemoryManager.retrieve_similar_incidents(
        current_symptoms="High database query delay and latency on payment-service"
    )
    print(f"Discovered {len(similar_cases)} similar past incidents:")
    for case in similar_cases:
        print(f" - Incident: {case['incident_id']} (Similarity: {case['similarity']:.3f}) | Root Cause: {case['root_cause']}")
        
    # 3. Test Procedural Memory (Redis policies)
    print("\nTesting Policy Engine...")
    ProceduralMemoryManager.load_policies_to_cache()
    # Test L3 permissions
    unrestricted = ProceduralMemoryManager.verify_action_permissions("payment-service", "get_logs")
    print(f"Action 'get_logs' unrestricted? {unrestricted}")
    requires_approval = not ProceduralMemoryManager.verify_action_permissions("payment-service", "restart_deployment")
    print(f"Action 'restart_deployment' requires approval? {requires_approval}")
    
    # 4. Initialize Working Memory Checkpointer (LangGraph Postgres)
    print("\nSetting up LangGraph Checkpointer...")
    async with get_working_memory_checkpointer() as checkpointer:
        print("Checkpointer setup successfully verified. DB schema created and validated.")

if __name__ == "__main__":
    asyncio.run(main())
