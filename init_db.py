import asyncio
import os
import psycopg

DB_URI = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres:secretpassword@localhost:5433/aegisops_db"
)

def setup_db():
    conn = psycopg.connect(DB_URI, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            print("Vector extension enabled.")
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS incident_memory (
                id SERIAL PRIMARY KEY,
                incident_id VARCHAR(255) UNIQUE NOT NULL,
                symptoms TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                actions_taken JSONB NOT NULL,
                outcome VARCHAR(50) NOT NULL,
                embedding vector(768) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            print("incident_memory table created.")
            
            cur.execute("""
            CREATE INDEX IF NOT EXISTS incident_memory_hnsw_idx 
            ON incident_memory USING hnsw (embedding vector_cosine_ops);
            """)
            print("incident_memory index created.")
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS runbooks (
                id SERIAL PRIMARY KEY,
                document_name VARCHAR(255) NOT NULL,
                chunk_text TEXT NOT NULL,
                embedding vector(768) NOT NULL
            );
            """)
            print("runbooks table created.")
            
            cur.execute("""
            CREATE INDEX IF NOT EXISTS runbooks_hnsw_idx 
            ON runbooks USING hnsw (embedding vector_cosine_ops);
            """)
            print("runbooks index created.")
            
            # ── MCP Firewall Audit Log ────────────────────────────────
            cur.execute("""
            CREATE TABLE IF NOT EXISTS firewall_audit_log (
                id SERIAL PRIMARY KEY,
                incident_id VARCHAR(255) NOT NULL,
                tool_name VARCHAR(255) NOT NULL,
                tool_args JSONB NOT NULL,
                entropy_score FLOAT NOT NULL,
                privilege_score FLOAT NOT NULL,
                deviation_score FLOAT NOT NULL,
                injection_match BOOLEAN NOT NULL,
                frequency_score FLOAT NOT NULL,
                composite_risk FLOAT NOT NULL,
                verdict VARCHAR(20) NOT NULL,
                matched_rules JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            print("firewall_audit_log table created.")
            
            cur.execute("""
            CREATE INDEX IF NOT EXISTS firewall_audit_incident_idx
            ON firewall_audit_log (incident_id);
            """)
            cur.execute("""
            CREATE INDEX IF NOT EXISTS firewall_audit_verdict_idx
            ON firewall_audit_log (verdict);
            """)
            print("firewall_audit_log indexes created.")
            
            print("Database successfully initialized.")
    finally:
        conn.close()

if __name__ == "__main__":
    setup_db()
