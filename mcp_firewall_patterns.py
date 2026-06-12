"""
mcp_firewall_patterns.py
=========================
Isolated pattern library for the AegisOps Semantic MCP Firewall.

Contains compiled regex rules for detecting dangerous SPL commands,
shell injection markers, sensitive REST endpoints, and a privilege
classification map that assigns a numeric tier (0.0–1.0) to every
known tool + SPL verb combination.

Kept in its own module so that security rules are auditable and
version-controllable independent of the scoring logic.
"""

import re
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# 1. Dangerous SPL Command Patterns
#    Matches destructive, exfiltrating, or privilege-escalating SPL verbs
#    that should NEVER be issued by an autonomous SRE agent.
# ---------------------------------------------------------------------------

DANGEROUS_SPL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Data destruction / modification
    ("spl_delete", re.compile(
        r"\|\s*delete\b", re.IGNORECASE
    )),
    ("spl_inputlookup_delete", re.compile(
        r"\|\s*inputlookup\s+.*\|\s*delete", re.IGNORECASE
    )),
    ("spl_outputlookup_overwrite", re.compile(
        r"\|\s*outputlookup\s+(?:override_if_empty\s*=\s*true|append\s*=\s*false)",
        re.IGNORECASE,
    )),

    # Privilege escalation via REST API
    ("spl_rest_auth", re.compile(
        r"\|\s*rest\s+.*/?services/authentication", re.IGNORECASE
    )),
    ("spl_rest_deployment", re.compile(
        r"\|\s*rest\s+.*/?services/deployment", re.IGNORECASE
    )),
    ("spl_rest_admin", re.compile(
        r"\|\s*rest\s+.*/?services/admin", re.IGNORECASE
    )),
    ("spl_rest_authorization", re.compile(
        r"\|\s*rest\s+.*/?services/authorization", re.IGNORECASE
    )),
    ("spl_rest_generic", re.compile(
        r"\|\s*rest\s+/services/", re.IGNORECASE
    )),

    # Arbitrary command execution
    ("spl_runshellscript", re.compile(
        r"\|\s*runshellscript\b", re.IGNORECASE
    )),
    ("spl_script", re.compile(
        r"\|\s*script\b", re.IGNORECASE
    )),
    ("spl_sendalert", re.compile(
        r"\|\s*sendalert\b", re.IGNORECASE
    )),

    # Data exfiltration
    ("spl_outputcsv", re.compile(
        r"\|\s*outputcsv\b", re.IGNORECASE
    )),
    ("spl_outputlookup", re.compile(
        r"\|\s*outputlookup\b", re.IGNORECASE
    )),
    ("spl_collect_exfil", re.compile(
        r"\|\s*collect\s+index\s*=", re.IGNORECASE
    )),
]

# ---------------------------------------------------------------------------
# 2. Shell Injection Patterns
#    Detects OS-level command injection markers that may be embedded
#    inside tool arguments by a compromised log stream or prompt injection.
# ---------------------------------------------------------------------------

SHELL_INJECTION_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Semicolon-chained command execution
    ("shell_semicolon_chain", re.compile(
        r";\s*(rm|cat|curl|wget|nc|ncat|python|bash|sh|powershell|cmd)\b",
        re.IGNORECASE,
    )),
    # Backtick subshell execution
    ("shell_backtick_exec", re.compile(
        r"`[^`]{2,}`"
    )),
    # Dollar-paren subshell execution
    ("shell_dollar_paren", re.compile(
        r"\$\([^)]{2,}\)"
    )),
    # Pipe to shell interpreter
    ("shell_pipe_interpreter", re.compile(
        r"\|\s*(bash|sh|python|perl|ruby|powershell|cmd)\b", re.IGNORECASE
    )),
    # Environment variable exfiltration
    ("shell_env_exfil", re.compile(
        r"\$\{?(HOME|PATH|USER|OPENAI_API_KEY|SPLUNK_TOKEN|AWS_SECRET|DATABASE_URL)\}?",
        re.IGNORECASE,
    )),
    # Common data exfiltration via curl/wget
    ("shell_data_exfil", re.compile(
        r"(curl|wget)\s+.*(http|https|ftp)://", re.IGNORECASE
    )),
]

# ---------------------------------------------------------------------------
# 3. Sensitive REST Endpoint Patterns
#    Matches Splunk management REST API paths that an SRE agent should
#    never autonomously query.
# ---------------------------------------------------------------------------

SENSITIVE_ENDPOINT_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("rest_authentication_users", re.compile(
        r"/services/authentication/users", re.IGNORECASE
    )),
    ("rest_authentication_tokens", re.compile(
        r"/services/authentication/(?:tokens|httpauth-tokens)", re.IGNORECASE
    )),
    ("rest_deployment_server", re.compile(
        r"/services/deployment/server", re.IGNORECASE
    )),
    ("rest_admin_conf", re.compile(
        r"/services/admin/conf-", re.IGNORECASE
    )),
    ("rest_licenser", re.compile(
        r"/services/licenser", re.IGNORECASE
    )),
    ("rest_cluster_config", re.compile(
        r"/services/cluster/config", re.IGNORECASE
    )),
]

# ---------------------------------------------------------------------------
# 4. Privilege Classification Map
#    Maps (tool_name, optional_verb) combinations to a privilege tier.
#    Scores range from 0.0 (harmless read-only) to 1.0 (maximum risk).
#
#    For Splunk MCP tools, the SPL command verb inside the query
#    arguments elevates the base tool privilege.
# ---------------------------------------------------------------------------

# Base privilege for known tool names (before verb analysis)
TOOL_PRIVILEGE_BASE: Dict[str, float] = {
    # Read-only / diagnostic
    "health_check":             0.00,
    "ping":                     0.00,
    "list_tools":               0.00,
    "splunk_get_info":          0.05,
    "get_logs":                 0.05,
    "get_pod_status":           0.10,
    "check_service_health":     0.10,
    "retrieve_runbook":         0.05,
    "splunk_get_indexes":       0.10,
    "splunk_get_index_info":    0.10,
    "splunk_get_metadata":      0.15,
    "splunk_get_user_info":     0.20,
    "current_user":             0.20,

    # Query execution (risk depends on SPL content)
    "splunk_run_query":         0.30,
    "run_splunk_query":         0.30,
    "search_splunk":            0.30,
    "generate_spl":             0.25,

    # Mutating / write operations
    "splunk_get_user_list":     0.40,
    "restart_deployment":       0.60,
    "update_deployment_image":  0.70,

    # KV Store write operations
    "splunk_create_kv_collection":  0.50,
    "splunk_delete_kv_collection":  0.80,

    # Knowledge object modification
    "splunk_get_knowledge_objects": 0.20,
}

# SPL verb privilege elevators — added to the base tool privilege (clamped to 1.0)
SPL_VERB_ELEVATORS: Dict[str, float] = {
    "rest":             0.60,
    "delete":           0.70,
    "runshellscript":   0.80,
    "script":           0.70,
    "outputlookup":     0.40,
    "outputcsv":        0.35,
    "sendalert":        0.50,
    "collect":          0.30,
    "inputlookup":      0.10,
    "lookup":           0.05,
    "stats":            0.00,
    "table":            0.00,
    "search":           0.00,
    "where":            0.00,
    "eval":             0.05,
    "rex":              0.05,
    "timechart":        0.00,
    "chart":            0.00,
    "head":             0.00,
    "tail":             0.00,
    "sort":             0.00,
    "dedup":            0.00,
    "fields":           0.00,
    "rename":           0.00,
    "top":              0.00,
    "rare":             0.00,
}


def get_privilege_score(tool_name: str, tool_args: dict) -> float:
    """Computes the privilege score for a tool call.

    For SPL-bearing tools (those containing a 'query' or 'search' argument),
    the score is elevated by the highest-privilege SPL verb found in the query.
    The final score is clamped to [0.0, 1.0].

    Args:
        tool_name: The MCP tool name being invoked.
        tool_args: The arguments dictionary for the tool call.

    Returns:
        A float in [0.0, 1.0] representing the privilege level.
    """
    base = TOOL_PRIVILEGE_BASE.get(tool_name, 0.50)  # Unknown tools default to 0.50

    # Extract SPL query string from common argument key names
    query_str = ""
    for key in ("query", "search", "search_query", "spl", "spl_query"):
        if key in tool_args and isinstance(tool_args[key], str):
            query_str = tool_args[key]
            break

    if not query_str:
        return min(base, 1.0)

    # Find the highest SPL verb elevator in the query
    max_elevation = 0.0
    query_lower = query_str.lower()
    for verb, elevation in SPL_VERB_ELEVATORS.items():
        # Match `| verb` pattern (piped SPL command)
        if re.search(rf"\|\s*{re.escape(verb)}\b", query_lower):
            max_elevation = max(max_elevation, elevation)

    return min(base + max_elevation, 1.0)


def scan_all_patterns(tool_name: str, tool_args: dict) -> Tuple[bool, List[str]]:
    """Scans a tool call against all pattern libraries.

    Serializes all tool arguments into a single text blob and runs
    every compiled regex against it. If any pattern matches, the call
    is flagged for instant blocking.

    Args:
        tool_name: The MCP tool name being invoked.
        tool_args: The arguments dictionary for the tool call.

    Returns:
        A tuple of (should_block: bool, matched_rule_names: List[str]).
    """
    # Serialize all argument values into a single searchable string
    searchable_parts: List[str] = [tool_name]
    for _key, value in tool_args.items():
        if isinstance(value, str):
            searchable_parts.append(value)
        elif isinstance(value, (list, dict)):
            # Flatten nested structures to catch deeply embedded payloads
            import json
            searchable_parts.append(json.dumps(value))
    searchable_text = "\n".join(searchable_parts)

    matched_rules: List[str] = []

    # Scan all pattern categories
    for rule_name, pattern in DANGEROUS_SPL_PATTERNS:
        if pattern.search(searchable_text):
            matched_rules.append(rule_name)

    for rule_name, pattern in SHELL_INJECTION_PATTERNS:
        if pattern.search(searchable_text):
            matched_rules.append(rule_name)

    for rule_name, pattern in SENSITIVE_ENDPOINT_PATTERNS:
        if pattern.search(searchable_text):
            matched_rules.append(rule_name)

    return (len(matched_rules) > 0, matched_rules)
