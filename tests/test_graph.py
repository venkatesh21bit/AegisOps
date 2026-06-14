import sys
import asyncio
import os

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

os.environ["OPENAI_API_KEY"] = "dummy"

from aegisops.agent.graph_builder import run_incident_workflow
from langchain_core.messages import AIMessage
import aegisops.agent.nodes

# Stateful mock LLM that simulates a realistic 3-step SRE workflow:
#   Step 1: Diagnose → call get_logs (unrestricted, will execute)
#   Step 2: Remediate → call restart_deployment (approval required, will HOLD)
#   Step 3: Resolve → emit a plain-text RCA summary (no tool calls → routes to resolution_node)
class MockModelWithTools:
    def __init__(self):
        self._call_count = 0

    async def ainvoke(self, messages, *args, **kwargs):
        self._call_count += 1

        if self._call_count == 1:
            # Step 1: Diagnostic — invoke an unrestricted tool
            return AIMessage(
                content="",
                tool_calls=[{"name": "get_logs", "args": {"service_name": "payment-service", "log_level": "error", "k": 3}, "id": "call_diag_001"}]
            )
        elif self._call_count == 2:
            # Step 2: Remediation — invoke a policy-gated mutating tool
            return AIMessage(
                content="",
                tool_calls=[{"name": "restart_deployment", "args": {"service_name": "payment-service", "namespace": "production"}, "id": "call_mut_002"}]
            )
        else:
            # Step 3: Resolution — no tool calls, plain text RCA triggers resolution_node
            return AIMessage(
                content=(
                    "Root Cause Analysis: Log analysis revealed high-frequency upstream connection timeouts "
                    "and transaction processing failures on payment-service. A rolling restart was requested "
                    "but requires manual human approval per L3 policy. Recommending operator sign-off."
                )
            )

aegisops.agent.nodes.model_with_tools = MockModelWithTools()

payload = {
    "incident_id": "INC-8822",
    "service_name": "payment-service",
    "autonomy_level": "L0",
    "namespace": "production"
}

if __name__ == "__main__":
    asyncio.run(run_incident_workflow(payload))
    
    # 1. Verify State Persistence in PostgreSQL
    print("\nVerifying Checkpoint Persistence in PostgreSQL:")
    import psycopg
    from aegisops.core.db_config import DB_URI
    with psycopg.connect(DB_URI) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT thread_id, checkpoint_id, parent_checkpoint_id FROM checkpoints WHERE thread_id = 'INC-8822';")
            rows = cur.fetchall()
            for r in rows:
                print(r)
