def dispatch_slack_approval_block(incident_id: str, service: str, action: str, args: dict, thread_id: str):
    print(f"[SLACK] Approval requested for {action} on {service} (Incident {incident_id})")

def send_resolution_summary(incident_id: str, service: str, actions_taken: list, audit_trail: list):
    print(f"[SLACK] Resolution Summary for {incident_id}: Actions {actions_taken}")
