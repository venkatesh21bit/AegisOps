import os
import psycopg
from pgvector.psycopg import register_vector
from psycopg.rows import dict_row

DB_URI = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres:secretpassword@localhost:5433/aegisops_db"
)

def get_db_connection():
    """Establishes and returns a synchronous database connection with vector support."""
    # Autocommit is required for schema creations and migrations
    conn = psycopg.connect(DB_URI, autocommit=True, row_factory=dict_row)
    # Register the pgvector type adapter globally for this connection
    register_vector(conn)
    return conn

async def get_async_db_connection():
    """Establishes and returns an asynchronous database connection with vector support."""
    conn = await psycopg.AsyncConnection.connect(DB_URI, autocommit=True, row_factory=dict_row)
    await register_vector(conn)
    return conn
