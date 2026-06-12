import json
import os
from typing import Dict, Any, List
from state import AegisOpsState
from episodic_memory import EpisodicMemoryManager
from semantic_memory import retrieve_runbook
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from tools_config import tools_list
from itsm_client import close_itsm_ticket
from slack_client import send_resolution_summary

async def memory_node(state: AegisOpsState) -> Dict[str, Any]:
    """Pre-loads contextual history from Episodic and Semantic memory layers.
    Injects past similar incidents and runbook instructions directly into the state."""
    print(f"[{state['incident_id']}] Running memory_node: Fetching system context...")
    
    # 1. Capture primary incident symptoms from the last user message
    last_user_msg = ""
    for msg in reversed(state["messages"]):
        if msg.type == "human":
            last_user_msg = str(msg.content)
            break
            
    if not last_user_msg:
        last_user_msg = f"Alert on {state['service_name']} in namespace {state['namespace']}"

    # 2. Query Episodic Memory (Cosine similarity distance threshold >= 0.72)
    similar_incidents = EpisodicMemoryManager.retrieve_similar_incidents(
        current_symptoms=last_user_msg,
        similarity_threshold=0.60,
        limit=2
    )
    
    episodic_blocks = []
    for idx, inc in enumerate(similar_incidents):
        episodic_blocks.append(
            f"--- Past Case #{idx+1} ({inc['incident_id']}) ---\n"
            f"Symptoms: {inc['symptoms']}\n"
            f"Root Cause: {inc['root_cause']}\n"
            f"Actions Taken: {inc['actions_taken']}\n"
            f"Outcome: {inc['outcome']}"
        )
    episodic_str = "\n\n".join(episodic_blocks) if episodic_blocks else "No past matching incident profiles discovered."

    # 3. Query Semantic Memory (RAG over Playbooks)
    # Programmatically run our retriever tool as an inline query
    runbook_data = retrieve_runbook.invoke({"query": f"{state['service_name']} latency error failed"})

    return {
        "episodic_context": episodic_str,
        "runbook_context": runbook_data,
        "retry_count": 0,
        "tool_audit_trail": []
    }

# Initialize the primary reasoning LLM
# Model-agnostic wrapper configured for OpenAI GPT-4o
llm = ChatOpenAI(
    model="gpt-4o",
    temperature=0.0,  # Deterministic reasoning for operations
    max_retries=3
)

# 16 tactical tools are bound directly to the model
model_with_tools = llm.bind_tools(tools_list)

# Master SRE System Prompt Template
SRE_SYSTEM_PROMPT = """You are AegisOps-SRE, a tireless, expert Autonomous SRE agent tasked with resolving system anomalies.
You operate under strict safety guidelines.

Your active target namespace is: {namespace}
Your active service context is: {service_name}
Active Incident ID: {incident_id}
Your Autonomy Tier: {autonomy_level}

--- COGNITIVE GUIDELINE: EPISODIC INCIDENT MEMORY ---
Use these historically resolved incidents to guide your current diagnostic paths. Do not repeat failed actions.
{episodic_context}

--- COGNITIVE GUIDELINE: SEMANTIC RUNBOOKS ---
Ground your commands in the following verified system runbooks:
{runbook_context}

--- REMEDIATION EXECUTION WORKFLOW ---
1. Observe the system telemetry using diagnostic tools (get_logs, get_pod_status).
2. Formulate your failure hypothesis and explain your logical thought process.
3. If an action is required, execute the specific tool. Some actions may require manual human sign-off; the tool executor will handle the gate.
4. Verify system health using 'check_service_health' before finalizing. If healthy, finish and write your final RCA summary.
"""

async def agent_node(state: AegisOpsState) -> Dict[str, Any]:
    """Generates the master prompt, binds tools, and triggers the LLM reasoning cycle."""
    print(f"[{state['incident_id']}] Running agent_node: Invoking LLM reasoning...")
    
    # Format the master system prompt with active memory contexts
    system_content = SRE_SYSTEM_PROMPT.format(
        namespace=state["namespace"],
        service_name=state["service_name"],
        incident_id=state["incident_id"],
        autonomy_level=state["autonomy_level"],
        episodic_context=state["episodic_context"],
        runbook_context=state["runbook_context"]
    )
    
    # Construct the message sequence
    messages = [SystemMessage(content=system_content)] + state["messages"]
    
    # Execute model prediction
    response = await model_with_tools.ainvoke(messages)
    
    return {"messages": [response]}

async def resolution_node(state: AegisOpsState) -> Dict[str, Any]:
    """Closes the incident lifecycle: saves the resolved state to Episodic memory, 
    resolves the ITSM ticket, and posts the final RCA to Slack.
    
    Includes MCP Firewall audit data (block/quarantine counts, matched rules)
    in the final RCA summary for full security observability."""
    print(f"[{state['incident_id']}] Running resolution_node: Closing incident...")
    
    # 1. Formulate the final RCA analysis string
    last_assistant_msg = ""
    for msg in reversed(state["messages"]):
        if msg.type == "ai":
            last_assistant_msg = str(msg.content)
            break
            
    # Calculate MTTR symptoms representation
    symptoms = f"Anomalous telemetry on service '{state['service_name']}' inside {state['namespace']}"
    
    # Extract executed tools list for permanent indexing
    actions_taken = [
        audit["tool"] for audit in state["tool_audit_trail"] if audit["status"] == "Executed"
    ]
    
    # ── Firewall Audit Summary ────────────────────────────────────────
    firewall_trail: List[Dict] = state.get("firewall_audit_trail", [])
    firewall_block_count = sum(
        1 for entry in firewall_trail
        if entry.get("verdict") == "BLOCK" or entry.get("source") == "mcp_firewall"
    )
    firewall_quarantine_count = sum(
        1 for entry in firewall_trail
        if entry.get("verdict") == "QUARANTINE"
    )
    firewall_summary = (
        f"MCP Firewall: {len(firewall_trail)} evaluations, "
        f"{firewall_block_count} blocks, {firewall_quarantine_count} quarantines."
    )
    
    # 2. Write to Episodic Memory (pgvector db commit)
    EpisodicMemoryManager.save_incident_memory(
        incident_id=state["incident_id"],
        symptoms=symptoms,
        root_cause=last_assistant_msg[:500],  # Capture root-cause summary
        actions=actions_taken,
        outcome="Resolved Successfully"
    )
    
    # 3. Synchronize State to ITSM (Close the incident ticket)
    close_itsm_ticket(
        ticket_id=state["incident_id"],
        resolution_notes=(
            f"AegisOps completed resolution loop. "
            f"Executed: {actions_taken}. {firewall_summary} "
            f"Summary: {last_assistant_msg[:200]}"
        )
    )
    
    # 4. Dispatch the final audit to Slack channel #all-aegisops
    send_resolution_summary(
        incident_id=state["incident_id"],
        service=state["service_name"],
        actions_taken=actions_taken,
        audit_trail=state["tool_audit_trail"]
    )
    
    return {"is_resolved": True}
