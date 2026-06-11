from typing import TypedDict, Annotated, List, Dict, Any
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

def merge_audit(old: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return old + new

class AegisOpsState(TypedDict):
    """The central state dictionary flowing through the AegisOps LangGraph state machine."""
    # add_messages appends new messages to the existing thread conversation list
    messages: Annotated[list[BaseMessage], add_messages]
    
    # Metadata context
    incident_id: str
    service_name: str
    autonomy_level: str
    namespace: str
    
    # Cognitive and contextual enrichment
    episodic_context: str
    runbook_context: str
    
    # Compliance and security audit trails
    tool_audit_trail: Annotated[List[Dict[str, Any]], merge_audit]
    
    # Resolution evaluation
    is_resolved: bool
    retry_count: int
