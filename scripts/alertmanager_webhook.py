import time
import subprocess
import urllib.request
import json

print("Starting Prometheus Alertmanager Simulator...")
print("Watching Kubernetes for pod crashes (ImagePullBackOff / CrashLoopBackOff)...")

def check_k8s_status():
    try:
        # Get pod status
        result = subprocess.run(
            ["kubectl", "get", "pods", "-l", "app=payment-service", "--no-headers"],
            capture_output=True, text=True
        )
        output = result.stdout
        
        if "ImagePullBackOff" in output or "CrashLoopBackOff" in output or "ErrImagePull" in output:
            return True
        return False
    except Exception as e:
        print(f"Failed to query kubectl: {e}")
        return False

def fire_webhook():
    url = "http://localhost:8001/incidents/trigger"
    payload = {
        "incident_id": "INC-LIVE-001",
        "service_name": "payment-service",
        "namespace": "default",
        "autonomy_level": "L3"
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    
    print("\n[Alertmanager] High Error Rate / CrashLoopBackOff Detected!")
    print(f"[Alertmanager] Firing Webhook to {url}...")
    
    try:
        response = urllib.request.urlopen(req)
        print(f"[Alertmanager] Webhook delivered successfully. Response Code: {response.getcode()}\n")
    except Exception as e:
        print(f"[Alertmanager] Failed to fire webhook: {e}")

if __name__ == "__main__":
    already_fired = False
    
    while True:
        is_crashing = check_k8s_status()
        
        if is_crashing and not already_fired:
            fire_webhook()
            already_fired = True
            
        elif not is_crashing and already_fired:
            # Reset if the deployment recovers
            print("[Alertmanager] Service recovered. Resetting alert state.")
            already_fired = False
            
        time.sleep(3)
