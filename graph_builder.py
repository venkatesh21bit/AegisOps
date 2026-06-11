import os
from langgraph.graph import StateGraph, START, END
from state import AegisOpsState
from nodes import memory_node, agent_node, resolution_node
from gated_tools import gated_tool_executor
from checkpointer import get_working_memory_checkpointer

def build_gated_sre_graph() -> StateGraph:
    """Instantiates, structures, and links the state nodes of AegisOps SRE."""
    workflow = StateGraph(AegisOpsState)
    
    # Register our nodes
    workflow.add_node("memory_loader", memory_node)
    workflow.add_node("cognitive_agent", agent_node)
    workflow.add_node("tool_gater", gated_tool_executor)
    workflow.add_node("remediation_closer", resolution_node)
    
    # Define execution pathways
    workflow.add_edge(START, "memory_loader")
    workflow.add_edge("memory_loader", "cognitive_agent")
    
    # Define conditional routing from the agent
    def router(state: AegisOpsState) -> str:
        last_message = state["messages"][-1]
        
        # If the LLM requested tools, route to tool_gater
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
            
        # Otherwise, the LLM has completed its work and verified system health
        return "close"
        
    workflow.add_conditional_edges(
        "cognitive_agent",
        router,
        {
            "tools": "tool_gater",
            "close": "remediation_closer"
        }
    )
    
    # After executing tools, always return to the agent node to evaluate outcomes
    workflow.add_edge("tool_gater", "cognitive_agent")
    workflow.add_edge("remediation_closer", END)
    
    return workflow

async def run_incident_workflow(incident_payload: dict):
    """Compiles the graph with the PostgreSQL checkpointer and runs the incident loop."""
    workflow = build_gated_sre_graph()
    
    # Retrieve the PostgreSQL checkpointer async context manager
    async with get_working_memory_checkpointer() as checkpointer:
        # Compile the state graph with our persistent checkpointer
        app = workflow.compile(checkpointer=checkpointer)
        
        # Establish the thread context (thread_id matches incident_id for state tracking)
        config = {"configurable": {"thread_id": incident_payload["incident_id"]}}
        
        # Initial message kickoff
        inputs = {
            "messages": [("user", f"Alert on {incident_payload['service_name']} in namespace {incident_payload['namespace']}")],
            "incident_id": incident_payload["incident_id"],
            "service_name": incident_payload["service_name"],
            "autonomy_level": incident_payload["autonomy_level"],
            "namespace": incident_payload["namespace"],
            "is_resolved": False
        }
        
        print(f"--- Triggering Autonomous SRE Run for {incident_payload['incident_id']} ---")
        async for output in app.astream(inputs, config, stream_mode="updates"):
            for node, state_update in output.items():
                print(f"Node '{node}' completed. Updated State Fields: {list(state_update.keys())}")
