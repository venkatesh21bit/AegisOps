import os
import time
import random
import json
import logging
import requests
import uuid
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown-service")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://host.docker.internal:8088/services/collector/event")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
LOG_RATE_MIN = float(os.getenv("LOG_RATE_MIN", "0.5"))
LOG_RATE_MAX = float(os.getenv("LOG_RATE_MAX", "2.0"))

logging.basicConfig(level=logging.INFO, format="%(message)s")

class LogGenerator:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json"
        })
        
        # Load behavior profile based on service name
        if SERVICE_NAME == "payment-service":
            self.error_rate = 0.05
            self.templates = [
                (logging.INFO, "Transaction {tx_id} completed successfully. Amount: ${amount}"),
                (logging.INFO, "Health check OK. CPU: {cpu}%, Mem: {mem}%"),
                (logging.DEBUG, "Cache miss for user {user_id}. Fetching from DB."),
                (logging.ERROR, "ERROR: Connection timeout to upstream payment gateway {ip_addr}"),
                (logging.ERROR, "FATAL: OutOfMemoryError in payment processing thread"),
            ]
        elif SERVICE_NAME == "auth-service":
            self.error_rate = 0.08
            self.templates = [
                (logging.INFO, "User {user_id} authenticated successfully from IP {ip_addr}"),
                (logging.INFO, "Token issued for session {tx_id}"),
                (logging.WARNING, "WARN: Invalid token format received from {ip_addr}"),
                (logging.ERROR, "ERROR: Identity provider unreachable. Backend 503"),
            ]
        elif SERVICE_NAME == "inventory-service":
            self.error_rate = 0.01
            self.templates = [
                (logging.INFO, "Stock updated for SKU-{tx_id}. Count: {amount}"),
                (logging.INFO, "Database synchronization complete. Latency: {cpu}ms"),
                (logging.DEBUG, "Running background cache flush for category 'Electronics'"),
                (logging.ERROR, "ERROR: Deadlock detected in inventory DB"),
            ]
        else:
            self.error_rate = 0.0
            self.templates = [(logging.INFO, "Generic heartbeat log from {tx_id}")]

    def generate_message(self):
        # Choose log level based on error rate
        is_error = random.random() < self.error_rate
        
        candidates = [t for t in self.templates if (t[0] >= logging.ERROR) == is_error]
        if not candidates:
            candidates = self.templates
            
        level, tmpl = random.choice(candidates)
        
        # Populate variables
        msg = tmpl.format(
            tx_id=str(uuid.uuid4())[:8],
            amount=random.randint(10, 5000),
            cpu=random.randint(10, 95),
            mem=random.randint(20, 99),
            user_id=f"usr_{random.randint(1000, 9999)}",
            ip_addr=f"192.168.1.{random.randint(1, 255)}"
        )
        
        # Add timestamp and level prefix
        level_str = logging.getLevelName(level)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S.000Z", time.gmtime())
        return f"{timestamp} {level_str} {msg}"

    def ship_to_splunk(self, raw_msg):
        if not SPLUNK_HEC_TOKEN:
            return
            
        payload = {
            "event": raw_msg,
            "sourcetype": f"kube:container:{SERVICE_NAME}",
            "source": "mock_generator",
            "host": "minikube-node-1",
            "time": time.time()
        }
        
        try:
            res = self.session.post(SPLUNK_HEC_URL, json=payload, verify=False, timeout=2.0)
            if res.status_code != 200:
                logging.warning(f"Failed to ship log to Splunk: {res.status_code} - {res.text}")
        except Exception as e:
            logging.error(f"HEC Connection Error: {e}")

    def run(self):
        logging.info(f"Starting log generator for {SERVICE_NAME}...")
        while True:
            msg = self.generate_message()
            logging.info(msg) # Print to stdout for docker logs
            self.ship_to_splunk(msg)
            
            time.sleep(random.uniform(LOG_RATE_MIN, LOG_RATE_MAX))

if __name__ == "__main__":
    generator = LogGenerator()
    generator.run()
