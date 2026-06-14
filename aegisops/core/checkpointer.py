import os
from contextlib import asynccontextmanager
from psycopg import AsyncConnection
from psycopg.rows import dict_row
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

DB_URI = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres:secretpassword@localhost:5433/aegisops_db?sslmode=disable"
)

# Enforce secure MSGPack parsing to prevent arbitrary code execution on deserialization
os.environ["LANGGRAPH_CHECKPOINT_ALLOW_DANGEROUS_DESERIALIZATION"] = "true"

@asynccontextmanager
async def get_working_memory_checkpointer():
    """Yields an active AsyncPostgresSaver instance for LangGraph checkpoint management."""
    # Connecting asynchronously with mandatory autocommit and dict row formatting
    async with await AsyncConnection.connect(
        DB_URI, 
        autocommit=True, # Required for setup migrations to run cleanly
        row_factory=dict_row # Required for dictionary key lookup inside checkpointer
    ) as conn:
        checkpointer = AsyncPostgresSaver(conn)
        # call setup() to automatically verify and create state tables
        await checkpointer.setup()
        yield checkpointer
