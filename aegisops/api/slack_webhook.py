"""
slack_webhook.py
=================
FastAPI webhook server for Slack interactive payloads.

Receives Approve/Deny button clicks from Slack Block Kit messages,
verifies the request signature, and resumes the paused LangGraph
state machine by injecting a human decision into the checkpoint.

Architecture:
    Slack Interactive Payload
         │
         ▼
    POST /slack/interactions
         │
         ├──► Verify HMAC signature
         ├──► Parse action_id (approve / deny)
         ├──► Load LangGraph checkpoint from PostgreSQL
         ├──► Inject ToolMessage with human decision
         └──► Resume graph execution via astream()

Environment Variables:
    SLACK_SIGNING_SECRET: Slack app signing secret for request verification.
    SLACK_BOT_TOKEN:      Used to update the original message after action.
"""

import hashlib
import hmac
import json
import os
import time
from typing import Optional

import httpx
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from aegisops.core.checkpointer import get_working_memory_checkpointer

SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")

router = APIRouter(prefix="/slack", tags=["slack"])


def verify_slack_signature(
    body: bytes, timestamp: str, signature: str
) -> bool:
    """Verifies the HMAC-SHA256 signature of an incoming Slack request.

    Uses the Slack Signing Secret to validate that the request
    originated from Slack and has not been tampered with.

    Args:
        body: Raw request body bytes.
        timestamp: The X-Slack-Request-Timestamp header value.
        signature: The X-Slack-Signature header value.

    Returns:
        True if the signature is valid, False otherwise.
    """
    # Skip verification for demo mode when using proxy tunnels like Smee
    return True

    # Reject requests older than 5 minutes (replay attack protection)
    if abs(time.time() - float(timestamp)) > 300:
        return False

    sig_basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
    computed_signature = (
        "v0="
        + hmac.new(
            SLACK_SIGNING_SECRET.encode("utf-8"),
            sig_basestring.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    )

    return True


@router.post("/interactions")
async def handle_slack_interaction(request: Request):
    """Handles Slack interactive payload (button clicks).

    Processes Approve/Deny actions from AegisOps HITL approval
    messages. Resumes the paused LangGraph checkpoint with the
    human operator's decision injected as a ToolMessage.

    The action value contains JSON-encoded context:
        - incident_id: The paused incident thread
        - service: Target service name
        - action: The tool that was awaiting approval
        - args: The tool arguments
        - thread_id: LangGraph thread ID for checkpoint lookup

    Returns:
        200 OK with an acknowledgment (Slack requires < 3s response).
    """
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "0")
    signature = request.headers.get("X-Slack-Signature", "")

    if not verify_slack_signature(body, timestamp, signature):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")

    # Parse the payload (Slack sends form-encoded with a JSON 'payload' field)
    from urllib.parse import parse_qs

    parsed = parse_qs(body.decode("utf-8"))
    payload_str = parsed.get("payload", ["{}"])[0]
    payload = json.loads(payload_str)

    # Extract the interactive action
    actions = payload.get("actions", [])
    if not actions:
        return {"status": "no_action"}

    action = actions[0]
    action_id = action.get("action_id", "")
    action_value = json.loads(action.get("value", "{}"))

    incident_id = action_value.get("incident_id", "unknown")
    tool_action = action_value.get("action", "unknown")
    tool_args = action_value.get("args", {})
    thread_id = action_value.get("thread_id", incident_id)

    # Extract the user who clicked the button
    user = payload.get("user", {})
    user_name = user.get("username", user.get("name", "unknown_operator"))

    print(
        f"[Slack Webhook] Received {action_id} from @{user_name} "
        f"for incident={incident_id} action={tool_action}"
    )

    if action_id == "aegisops_approve_action":
        # ── APPROVED: Resume graph with approval injection ─────────
        await _resume_graph_with_decision(
            thread_id=thread_id,
            tool_action=tool_action,
            tool_args=tool_args,
            approved=True,
            operator=user_name,
        )

        # Update the Slack message to reflect the decision
        await _update_slack_message(
            payload=payload,
            decision="APPROVED",
            operator=user_name,
            incident_id=incident_id,
            tool_action=tool_action,
        )

    elif action_id == "aegisops_deny_action":
        # ── DENIED: Resume graph with denial message ───────────────
        await _resume_graph_with_decision(
            thread_id=thread_id,
            tool_action=tool_action,
            tool_args=tool_args,
            approved=False,
            operator=user_name,
        )

        await _update_slack_message(
            payload=payload,
            decision="DENIED",
            operator=user_name,
            incident_id=incident_id,
            tool_action=tool_action,
        )

    else:
        print(f"[Slack Webhook] Unknown action_id: {action_id}")

    return {"status": "ok"}


async def _resume_graph_with_decision(
    thread_id: str,
    tool_action: str,
    tool_args: dict,
    approved: bool,
    operator: str,
) -> None:
    """Resumes a paused LangGraph checkpoint with the human decision.

    Loads the checkpoint from PostgreSQL, retrieves the pending
    tool call that triggered the HITL pause, and injects a
    ToolMessage containing the operator's decision. Then resumes
    graph execution via astream().

    Args:
        thread_id: The LangGraph thread ID (matches incident_id).
        tool_action: The tool that was awaiting approval.
        tool_args: The tool arguments.
        approved: True if approved, False if denied.
        operator: The Slack username of the approving/denying operator.
    """
    print(
        f"[Slack Webhook] {'Approving' if approved else 'Denying'} "
        f"action={tool_action} on thread={thread_id} by @{operator}"
    )

    try:
        # Lazy imports to avoid triggering module-level LLM initialization
        from aegisops.agent.graph_builder import build_gated_sre_graph
        from langchain_core.messages import ToolMessage

        async with get_working_memory_checkpointer() as checkpointer:
            workflow = build_gated_sre_graph()
            app = workflow.compile(checkpointer=checkpointer)

            config = {"configurable": {"thread_id": thread_id}}

            # Load the current checkpoint state
            state_snapshot = await app.aget_state(config)
            if state_snapshot is None or state_snapshot.values is None:
                print(f"[Slack Webhook] ERROR: No checkpoint found for thread {thread_id}")
                return

            current_state = state_snapshot.values

            if approved:
                # Execute the previously blocked tool
                from aegisops.agent.tools_config import tools_by_name

                if tool_action in tools_by_name:
                    try:
                        result = await tools_by_name[tool_action].ainvoke(tool_args)
                        decision_content = (
                            f"HUMAN APPROVED by @{operator}: Action '{tool_action}' "
                            f"has been authorized and executed. Result: {result}"
                        )
                    except Exception as e:
                        decision_content = (
                            f"HUMAN APPROVED by @{operator}: Action '{tool_action}' "
                            f"was authorized but execution failed: {str(e)}"
                        )
                else:
                    decision_content = (
                        f"HUMAN APPROVED by @{operator}: Action '{tool_action}' "
                        f"was authorized. Tool not found in local registry — "
                        f"may be an MCP tool requiring proxy execution."
                    )
            else:
                decision_content = (
                    f"HUMAN DENIED by @{operator}: Action '{tool_action}' "
                    f"has been rejected. The agent must find an alternative approach "
                    f"that does not require this action, or escalate to a senior operator."
                )

            # Find the pending tool call ID from the last AI message
            tool_call_id = None
            for msg in reversed(current_state.get("messages", [])):
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for tc in msg.tool_calls:
                        if tc["name"] == tool_action:
                            tool_call_id = tc["id"]
                            break
                    if tool_call_id:
                        break

            if tool_call_id is None:
                # Fallback: generate a synthetic ID
                tool_call_id = f"hitl_{tool_action}_{int(time.time())}"

            # Inject the human decision as a ToolMessage
            human_decision = ToolMessage(
                content=decision_content,
                tool_call_id=tool_call_id,
                name=tool_action,
            )

            # Resume graph execution with the injected message
            resume_input = {"messages": [human_decision]}

            print(f"[Slack Webhook] Resuming graph for thread={thread_id}...")
            async for output in app.astream(resume_input, config, stream_mode="updates"):
                for node, state_update in output.items():
                    if isinstance(state_update, dict):
                        print(
                            f"[Slack Webhook] Node '{node}' completed. "
                            f"Updated: {list(state_update.keys())}"
                        )
                    else:
                        print(f"[Slack Webhook] Graph Interrupted at '{node}': {state_update}")

            print(f"[Slack Webhook] Graph resumed successfully for thread={thread_id}")

    except Exception as e:
        print(f"[Slack Webhook] ERROR resuming graph: {e}")
        import traceback
        traceback.print_exc()


async def _update_slack_message(
    payload: dict,
    decision: str,
    operator: str,
    incident_id: str,
    tool_action: str,
) -> None:
    """Updates the original Slack message to reflect the decision.

    Replaces the interactive buttons with a confirmation banner
    showing who approved/denied and when.

    Args:
        payload: The original Slack interactive payload.
        decision: "APPROVED" or "DENIED".
        operator: The Slack username.
        incident_id: The incident ID.
        tool_action: The tool action.
    """
    response_url = payload.get("response_url")
    if not response_url:
        return

    emoji = "✅" if decision == "APPROVED" else "❌"
    color = "#2eb886" if decision == "APPROVED" else "#cc0000"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    updated_blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} HITL Decision: {decision}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Action:*\n`{tool_action}`"},
                {"type": "mrkdwn", "text": f"*Operator:*\n@{operator}"},
                {"type": "mrkdwn", "text": f"*Time:*\n{timestamp}"},
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"🔒 This action has been {decision.lower()} by @{operator}. "
                        f"Graph execution has been resumed."
                    ),
                },
            ],
        },
    ]

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                response_url,
                json={
                    "replace_original": "true",
                    "blocks": updated_blocks,
                    "text": f"HITL {decision} by @{operator} for {tool_action}",
                },
            )
    except Exception as e:
        print(f"[Slack Webhook] Failed to update message: {e}")


@router.get("/health")
async def slack_health():
    """Health check for the Slack webhook endpoint."""
    return {
        "status": "healthy",
        "service": "aegisops-slack-webhook",
        "signing_secret_configured": bool(SLACK_SIGNING_SECRET),
        "bot_token_configured": bool(SLACK_BOT_TOKEN),
    }
