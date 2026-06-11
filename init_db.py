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
            
            print("Database successfully initialized.")
    finally:
        conn.close()

if __name__ == "__main__":
    setup_db()
