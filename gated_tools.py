import json
import time
from typing import Dict, Any
from state import AegisOpsState
from procedural_memory import ProceduralMemoryManager
from tools_config import tools_by_name
from langchain_core.messages import ToolMessage
from langgraph.prebuilt import InjectedState
from slack_client import dispatch_slack_approval_block  # Slack helper

async def gated_tool_executor(state: AegisOpsState) -> Dict[str, Any]:
    """Gated tool router. Intercepts calls, validates against Redis policies, 
    and prompts Slack HITL workflows if approval is needed."""
    
    # Extract the last message which contains the requested tool calls
    last_message = state["messages"][-1]
    if not hasattr(last_message, "tool_calls") or not last_message.tool_calls:
        return {"messages": []}
        
    outputs = []
    tool_audit = []
    
    for tool_call in last_message.tool_calls:
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]
        tool_id = tool_call["id"]
        
        print(f"[{state['incident_id']}] Evaluating Policy for: {tool_name} with args {tool_args}")
        
        # Inject context-sensitive parameters if they are missing
        if "service_name" not in tool_args:
            tool_args["service_name"] = state["service_name"]
        if "namespace" not in tool_args:
            tool_args["namespace"] = state["namespace"]
            
        start_time = time.time()
        
        try:
            # 1. Query Procedural Memory (Redis Cache Validator)
            # Returns: True (autonomous execution), False (Slack approval required)
            is_allowed_autonomous = ProceduralMemoryManager.verify_action_permissions(
                service_name=state["service_name"],
                requested_action=tool_name
            )
            
            if is_allowed_autonomous:
                # Execute autonomously
                result = await tools_by_name[tool_name].ainvoke(tool_args)
                status = "Executed"
            else:
                # 2. L3 Human-In-The-Loop Approval Gate Triggered
                print(f"[{state['incident_id']}] HITL Triggered: Pausing execution. Dispatching Slack Approval...")
                
                # Push the Block Kit UI payload to Slack
                dispatch_slack_approval_block(
                    incident_id=state["incident_id"],
                    service=state["service_name"],
                    action=tool_name,
                    args=tool_args,
                    thread_id=state["incident_id"] # Thread matches unique incident
                )
                
                # Force LangGraph to halt. We return an error-like message instructing the LLM 
                # that execution is suspended pending human sign-off.
                result = (
                    f"CRITICAL STATE: This action ({tool_name}) requires human operator validation. "
                    f"The graph execution has been paused and a manual sign-off request has been sent to Slack. "
                    f"Await manual approval."
                )
                status = "Paused"
                
        except Exception as e:
            result = f"Tool Execution Aborted: {str(e)}"
            status = "Blocked"
            
        latency = time.time() - start_time
        
        # 3. Compile audit payload
        audit_entry = {
            "tool": tool_name,
            "args": tool_args,
            "status": status,
            "latency_seconds": round(latency, 3),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        tool_audit.append(audit_entry)
        
        outputs.append(
            ToolMessage(
                content=str(result),
                tool_call_id=tool_id,
                name=tool_name
            )
        )
        
    return {
        "messages": outputs,
        "tool_audit_trail": tool_audit
    }
