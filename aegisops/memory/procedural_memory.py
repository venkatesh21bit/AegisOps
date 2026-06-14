import os
import yaml
import redis
from typing import Any, Dict, Optional
from langchain_core.tools import ToolException

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

class ProceduralMemoryManager:
    @staticmethod
    def load_policies_to_cache(file_path: str = "params.yml"):
        """Loads and parses local YAML configuration into the active Redis cache.
        
        Caches both the service restriction policies and the MCP firewall
        configuration so they can be read at runtime without filesystem access.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Missing procedural policy rules file: {file_path}")
            
        with open(file_path, "r", encoding="utf-8") as f:
            policies = yaml.safe_load(f)
            
        # Write service restriction rules to Redis
        redis_client.set("global_autonomy_level", policies.get("autonomy_level", "L3"))
        redis_client.set("service_restrictions", yaml.dump(policies.get("service_restrictions", [])))
        
        # Write MCP firewall configuration to Redis
        firewall_config = policies.get("firewall", {})
        if firewall_config:
            redis_client.set("firewall_config", yaml.dump(firewall_config))
            print("MCP Firewall configuration cached in Redis.")
        
        print("Procedural memory successfully initialized inside Redis.")

    @staticmethod
    def get_firewall_config() -> Dict[str, Any]:
        """Reads and deserializes the cached firewall config from Redis.
        
        Returns safe fallback defaults if the cache is empty or Redis
        is unreachable, ensuring the firewall never fails open due to
        a cache miss.
        
        Returns:
            Firewall configuration dictionary with weights, thresholds,
            rate limits, and schema drift settings.
        """
        from aegisops.mcp.mcp_firewall import DEFAULT_FIREWALL_CONFIG
        
        try:
            cached = redis_client.get("firewall_config")
            if cached:
                config = yaml.safe_load(cached)
                if isinstance(config, dict):
                    return config
        except Exception as e:
            print(f"[ProceduralMemory] WARNING: Failed to read firewall config from Redis: {e}")
        
        return DEFAULT_FIREWALL_CONFIG

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

