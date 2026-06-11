import os
import yaml
import redis
from langchain_core.tools import ToolException

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

class ProceduralMemoryManager:
    @staticmethod
    def load_policies_to_cache(file_path: str = "params.yml"):
        """Loads and parses local YAML configuration into the active Redis cache."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Missing procedural policy rules file: {file_path}")
            
        with open(file_path, "r") as f:
            policies = yaml.safe_load(f)
            
        # Write rules to Redis
        redis_client.set("global_autonomy_level", policies.get("autonomy_level", "L3"))
        redis_client.set("service_restrictions", yaml.dump(policies.get("service_restrictions", [])))
        print("Procedural memory successfully initialized inside Redis.")

    @staticmethod
    def verify_action_permissions(service_name: str, requested_action: str) -> bool:
        """Evaluates whether an SRE tool call complies with active guardrails.
        Returns True if authorized, False if approval is required. Raises Exception if blocked."""
        autonomy_level = redis_client.get("global_autonomy_level") or "L3"
        cached_restrictions = redis_client.get("service_restrictions")
        
        if not cached_restrictions:
            raise ToolException("Procedural validation failed: Service policies are uninitialized.")
            
        restrictions = yaml.safe_load(cached_restrictions)
        
        # Locate target service restriction configuration
        service_policy = next((r for r in restrictions if r["service"] == service_name), None)
        
        # Default safety fallback: if undefined, block mutating tasks
        if not service_policy:
            raise ToolException(f"Procedural Gatekeeper: No policy definition exists for service: {service_name}.")
            
        # L0 Autonomy - Permanently block any mutating action
        if autonomy_level == "L0" and requested_action not in ["get_logs", "get_pod_status"]:
            raise ToolException("Unauthorized Action: Platform is executing under read-only L0 limits.")
            
        # Evaluate service-specific capabilities
        if requested_action in service_policy.get("unrestricted_actions", []):
            return True # Action can execute autonomously
            
        if requested_action in service_policy.get("approval_required_actions", []):
            return False # Gatekeepers must pause and route to Slack for HITL validation
            
        raise ToolException(
            f"Policy Violated: The SRE Agent is permanently forbidden from executing "
            f"'{requested_action}' on service '{service_name}'."
        )
