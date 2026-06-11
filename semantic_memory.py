from sentence_transformers import SentenceTransformer
from langchain_core.tools import tool
from db_config import get_db_connection

encoder = SentenceTransformer("all-mpnet-base-v2")

class SemanticMemoryManager:
    @staticmethod
    def ingest_runbook_chunk(doc_name: str, chunk_text: str):
        """Helper tool to index split runbook segments."""
        embedding = encoder.encode(chunk_text).tolist()
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO runbooks (document_name, chunk_text, embedding)
                    VALUES (%s, %s, %s::vector);
                """, (doc_name, chunk_text, embedding))
        finally:
            conn.close()

@tool
def retrieve_runbook(query: str) -> str:
    """Semantic search over engineering playbooks and infrastructure runbooks. 
    Surfaces the top 4 most matching text blocks exceeding a similarity score of 0.75."""
    query_vector = encoder.encode(query).tolist()
    conn = get_db_connection()
    
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT document_name, chunk_text, (1 - (embedding <=> %s::vector)) AS similarity
                FROM runbooks
                WHERE (1 - (embedding <=> %s::vector)) >= 0.60
                ORDER BY similarity DESC
                LIMIT 4;
            """, (query_vector, query_vector))
            records = cur.fetchall()
            
            if not records:
                return "No matching system runbooks discovered for the specified query."
                
            formatted_outputs = []
            for r in records:
                formatted_outputs.append(
                    f"--- Source: {r['document_name']} (Similarity: {r['similarity']:.3f}) ---\n{r['chunk_text']}"
                )
            return "\n\n".join(formatted_outputs)
    finally:
        conn.close()
