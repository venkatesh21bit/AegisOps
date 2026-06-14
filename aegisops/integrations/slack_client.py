"""
slack_client.py
================
Production Slack SDK client for AegisOps.

Sends rich Block Kit approval messages for HITL gating decisions
and posts resolution summaries with full audit trail details.
Uses the Slack Web API via httpx for async-compatible HTTP calls.

All Slack interactions use Block Kit interactive components with
action IDs that the webhook server (slack_webhook.py) maps back
to LangGraph checkpoint resume operations.

Environment Variables:
    SLACK_BOT_TOKEN:      xoxb-... OAuth token with chat:write scope.
    SLACK_CHANNEL_ID:     Channel ID for #aegisops-alerts (default: general).
    SLACK_SIGNING_SECRET: Used by the webhook to verify request authenticity.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

import httpx

SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL_ID = os.getenv("SLACK_CHANNEL_ID", "general")
SLACK_API_BASE = "https://slack.com/api"


def _post_slack_message(blocks: list, text: str, thread_ts: Optional[str] = None) -> dict:
    """Posts a Block Kit message to the configured Slack channel.

    Args:
        blocks: Slack Block Kit block array.
        text: Fallback plain-text for notifications.
        thread_ts: Optional thread timestamp for threading replies.

    Returns:
        Slack API response as a dictionary.
    """
    if not SLACK_BOT_TOKEN or SLACK_BOT_TOKEN == "xoxb-your-slack-bot-token":
        # Graceful fallback when Slack is not configured
        print(f"[SLACK] (Mock Mode) {text}")
        print(f"[SLACK] Blocks: {json.dumps(blocks, indent=2)[:500]}")
        return {"ok": True, "mock": True}

    payload: Dict[str, Any] = {
        "channel": SLACK_CHANNEL_ID,
        "blocks": blocks,
        "text": text,
    }
    if thread_ts:
        payload["thread_ts"] = thread_ts

    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.post(
                f"{SLACK_API_BASE}/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            result = response.json()
            if not result.get("ok"):
                print(f"[SLACK] API Error: {result.get('error', 'unknown')}")
            return result
    except Exception as e:
        print(f"[SLACK] Failed to post message: {e}")
        return {"ok": False, "error": str(e)}


def dispatch_slack_approval_block(
    incident_id: str,
    service: str,
    action: str,
    args: dict,
    thread_id: str,
) -> dict:
    """Sends an interactive Block Kit approval request to Slack.

    The message includes Approve and Deny buttons with action IDs
    that encode the incident context. The webhook server
    (slack_webhook.py) uses these to resume the LangGraph checkpoint.

    Args:
        incident_id: The active incident ID.
        service: The target service name.
        action: The tool action requiring approval.
        args: The tool arguments (displayed in the message).
        thread_id: Thread identifier for grouping messages.

    Returns:
        Slack API response dictionary.
    """
    # Encode context into action value for the webhook to parse
    action_context = json.dumps({
        "incident_id": incident_id,
        "service": service,
        "action": action,
        "args": args,
        "thread_id": thread_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    # Format args for display (truncate long values)
    args_display = "\n".join(
        f"• `{k}`: {str(v)[:100]}" for k, v in args.items()
    )

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🛡️ AegisOps HITL Approval Required",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Service:*\n`{service}`"},
                {"type": "mrkdwn", "text": f"*Action:*\n`{action}`"},
                {"type": "mrkdwn", "text": f"*Autonomy Level:*\n`L3 (HITL Required)`"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Arguments:*\n{args_display}",
            },
        },
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"⏳ Graph execution is *paused*. The agent is waiting "
                        f"for operator sign-off before proceeding."
                    ),
                },
            ],
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
                    "style": "primary",
                    "action_id": "aegisops_approve_action",
                    "value": action_context,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ Deny", "emoji": True},
                    "style": "danger",
                    "action_id": "aegisops_deny_action",
                    "value": action_context,
                },
            ],
        },
    ]

    fallback_text = (
        f"AegisOps HITL: Approval needed for '{action}' on {service} "
        f"(Incident: {incident_id})"
    )

    return _post_slack_message(blocks, fallback_text, thread_ts=None)


def send_resolution_summary(
    incident_id: str,
    service: str,
    actions_taken: list,
    audit_trail: list,
) -> dict:
    """Posts a rich resolution summary to Slack.

    Includes the full audit trail of executed tools, latencies,
    and the overall resolution status.

    Args:
        incident_id: The resolved incident ID.
        service: The target service name.
        actions_taken: List of tool names that were executed.
        audit_trail: Full audit trail with timestamps and latencies.

    Returns:
        Slack API response dictionary.
    """
    # Format audit trail for display
    audit_lines = []
    for entry in audit_trail[:10]:  # Cap at 10 entries for readability
        tool = entry.get("tool", "unknown")
        status = entry.get("status", "?")
        latency = entry.get("latency_seconds", 0)
        emoji = "✅" if status == "Executed" else "⏸️" if status == "Paused" else "🔥"
        audit_lines.append(f"{emoji} `{tool}` — {status} ({latency:.2f}s)")

    audit_display = "\n".join(audit_lines) if audit_lines else "No actions recorded."

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🎯 AegisOps Incident Resolved",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Service:*\n`{service}`"},
                {
                    "type": "mrkdwn",
                    "text": f"*Actions Executed:*\n{len(actions_taken)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Status:*\n✅ Resolved",
                },
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Audit Trail:*\n{audit_display}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🔒 Powered by AegisOps Semantic MCP Firewall",
                },
            ],
        },
    ]

    fallback_text = (
        f"AegisOps Resolved: {incident_id} on {service}. "
        f"Actions: {actions_taken}"
    )

    return _post_slack_message(blocks, fallback_text)


def send_firewall_alert(
    incident_id: str,
    tool_name: str,
    verdict: str,
    risk_score: float,
    matched_rules: list,
) -> dict:
    """Posts a firewall verdict alert to Slack.

    Used for BLOCK and QUARANTINE verdicts from the MCP Firewall
    to give operators real-time visibility into security events.

    Args:
        incident_id: The active incident ID.
        tool_name: The tool that was evaluated.
        verdict: The firewall verdict (BLOCK/QUARANTINE).
        risk_score: The composite risk score.
        matched_rules: List of matched pattern rule names.

    Returns:
        Slack API response dictionary.
    """
    color = "danger" if verdict == "BLOCK" else "warning"
    emoji = "🚫" if verdict == "BLOCK" else "⚠️"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} MCP Firewall {verdict}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Tool:*\n`{tool_name}`"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n`{risk_score:.3f}`"},
                {
                    "type": "mrkdwn",
                    "text": f"*Matched Rules:*\n`{', '.join(matched_rules)}`",
                },
            ],
        },
    ]

    fallback_text = (
        f"MCP Firewall {verdict}: {tool_name} blocked "
        f"(risk={risk_score:.3f}, rules={matched_rules})"
    )

    return _post_slack_message(blocks, fallback_text)
