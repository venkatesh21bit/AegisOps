"""
main.py
========
AegisOps Unified API Server.

FastAPI application serving as the central orchestration entrypoint:
    - POST /incidents/trigger  →  Launches a new autonomous SRE workflow
    - POST /slack/interactions →  Receives Slack HITL button clicks
    - GET  /health             →  System health check
    - GET  /slack/health       →  Slack webhook health check

Usage:
    .venv\\Scripts\\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

    Or directly:
    .venv\\Scripts\\python.exe main.py
"""

import asyncio
import os
import sys
import json
import time
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, Field

app = FastAPI(
    title="AegisOps SRE Agent",
    description=(
        "MCP-enabled Agentic Middleware with Semantic Firewall, "
        "Cognitive Memory, and Human-in-the-Loop Safety Gates."
    ),
    version="0.1.0",
)

# ── Mount Slack Webhook Router ────────────────────────────────────────
from aegisops.api.slack_webhook import router as slack_router

app.include_router(slack_router)


# ── Request/Response Models ───────────────────────────────────────────

class IncidentPayload(BaseModel):
    """Payload to trigger a new SRE incident workflow."""

    incident_id: str = Field(
        ..., description="Unique incident identifier (e.g., INC-2026-0042)"
    )
    service_name: str = Field(
        ..., description="Target service name (must match params.yml restrictions)"
    )
    namespace: str = Field(
        default="default", description="Kubernetes namespace"
    )
    autonomy_level: str = Field(
        default="L3",
        description="Autonomy tier: L0 (read-only), L1, L2, L3 (HITL for mutating)",
    )


class IncidentResponse(BaseModel):
    """Response after triggering an incident workflow."""

    status: str
    incident_id: str
    message: str


class HealthResponse(BaseModel):
    """System health status."""

    status: str
    service: str
    version: str
    redis_connected: bool
    components: dict


# ── Startup Event ─────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    """Initializes procedural memory policies on server start.

    Loads params.yml into Redis so that the policy engine and
    firewall are immediately ready to serve requests.
    """
    try:
        from aegisops.memory.procedural_memory import ProceduralMemoryManager
        ProceduralMemoryManager.load_policies_to_cache()
        print("[AegisOps] Procedural memory and firewall config loaded to Redis.")
    except Exception as e:
        print(f"[AegisOps] WARNING: Failed to load policies: {e}")
        print("[AegisOps] Ensure Redis is running (docker-compose up -d)")


# ── Incident Trigger Endpoint ─────────────────────────────────────────

@app.post("/incidents/trigger", response_model=IncidentResponse)
async def trigger_incident(
    payload: IncidentPayload, background_tasks: BackgroundTasks
):
    """Launches a new autonomous SRE remediation workflow.

    The workflow runs as a background task so the API responds
    immediately. The graph state is persisted to PostgreSQL via
    the LangGraph checkpointer, enabling pause/resume for HITL.

    Args:
        payload: The incident details.
        background_tasks: FastAPI background task manager.

    Returns:
        Acknowledgment with the incident ID and status.
    """
    print(
        f"[AegisOps] Incident triggered: {payload.incident_id} "
        f"on {payload.service_name} ({payload.namespace})"
    )

    # Lazy import to avoid module-level LLM initialization
    from aegisops.agent.graph_builder import run_incident_workflow

    # Launch the graph execution as a background task
    background_tasks.add_task(
        run_incident_workflow,
        {
            "incident_id": payload.incident_id,
            "service_name": payload.service_name,
            "namespace": payload.namespace,
            "autonomy_level": payload.autonomy_level,
        },
    )

    return IncidentResponse(
        status="triggered",
        incident_id=payload.incident_id,
        message=(
            f"Autonomous SRE workflow launched for {payload.service_name}. "
            f"Graph state is persisted — HITL gates will pause and resume via Slack."
        ),
    )


# ── Health Check ──────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Returns the system health status including Redis connectivity."""
    redis_ok = False
    try:
        from aegisops.memory.procedural_memory import redis_client

        redis_client.ping()
        redis_ok = True
    except Exception:
        pass

    return HealthResponse(
        status="healthy" if redis_ok else "degraded",
        service="aegisops-sre-agent",
        version="0.1.0",
        redis_connected=redis_ok,
        components={
            "procedural_memory": "redis",
            "episodic_memory": "pgvector",
            "semantic_memory": "pgvector",
            "checkpointer": "postgresql",
            "mcp_firewall": "inline_proxy",
            "slack_webhook": "fastapi",
        },
    )


# ── Direct Execution ──────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    uvicorn.run(
        "aegisops.api.main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info",
    )
