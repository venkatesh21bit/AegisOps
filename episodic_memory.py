import json
from sentence_transformers import SentenceTransformer
from db_config import get_db_connection

# Initialize the 768-dimension local embedding model
encoder = SentenceTransformer("all-mpnet-base-v2")

class EpisodicMemoryManager:
    @staticmethod
    def save_incident_memory(incident_id: str, symptoms: str, root_cause: str, actions: list, outcome: str):
        """Saves a resolved incident and its vector embedding into episodic memory."""
        # Concatenate symptoms and root cause to create a rich contextual trace
        context_string = f"Symptoms: {symptoms} | Root Cause: {root_cause}"
        embedding = encoder.encode(context_string).tolist()
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO incident_memory (incident_id, symptoms, root_cause, actions_taken, outcome, embedding)
                    VALUES (%s, %s, %s, %s, %s, %s::vector)
                    ON CONFLICT (incident_id) DO UPDATE 
                    SET root_cause = EXCLUDED.root_cause, actions_taken = EXCLUDED.actions_taken, outcome = EXCLUDED.outcome;
                """, (incident_id, symptoms, root_cause, json.dumps(actions), outcome, embedding))
            print(f"Successfully committed episodic memory for incident: {incident_id}")
        finally:
            conn.close()

    @staticmethod
    def retrieve_similar_incidents(current_symptoms: str, similarity_threshold: float = 0.6, limit: int = 3) -> list:
        """Surfaces up to top 3 historical cases matching the current incident."""
        query_embedding = encoder.encode(current_symptoms).tolist()
        conn = get_db_connection()
        
        try:
            with conn.cursor() as cur:
                # pgvector <=> operator calculates cosine distance. 
                # Similarity is calculated mathematically as: 1 - cosine_distance
                cur.execute("""
                    SELECT incident_id, symptoms, root_cause, actions_taken, outcome,
                           (1 - (embedding <=> %s::vector)) AS similarity
                    FROM incident_memory
                    WHERE (1 - (embedding <=> %s::vector)) >= %s
                    ORDER BY similarity DESC
                    LIMIT %s;
                """, (query_embedding, query_embedding, similarity_threshold, limit))
                results = cur.fetchall()
                return results
        finally:
            conn.close()
