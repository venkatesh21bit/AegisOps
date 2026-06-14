import time
import random
import uuid
import os

# Windows-compatible path within the project
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file_path = os.path.join(log_dir, "payment-service.log")

ips = ["10.0.1.42", "10.0.1.99", "10.244.0.15", "10.244.1.8"]

errors = [
    "ERROR: connection to upstream [IP] timeout after 30s",
    "ERROR: failed to process transaction for transaction_id=[TX_ID] - insufficient funds",
    "WARN: slow query response on SELECT * FROM transactions WHERE user_id=[NUM]",
    "INFO: health check passed for payments system",
    "ERROR: pod [IP] OOMKilled - memory limit exceeded during batch processing",
    "WARN: Redis cache miss for session_id=[TX_ID] - falling back to DB",
    "ERROR: TLS handshake failed with upstream [IP]:443 - certificate expired",
    "INFO: deployment rollout progressing - [NUM] of 2 replicas available",
]

print(f"Starting local mock log generator...")
print(f"Writing logs to: {log_file_path}")

with open(log_file_path, "a") as f:
    while True:
        # Simulate timestamp, random IP, UUID, and pattern
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        ip = random.choice(ips)
        tx_id = str(uuid.uuid4())
        num = str(random.randint(1000, 9999))

        log_template = random.choice(errors)
        log_message = (
            log_template
            .replace("[IP]", ip)
            .replace("[TX_ID]", tx_id)
            .replace("[NUM]", num)
        )

        f.write(f"{timestamp} {log_message}\n")
        f.flush()
        time.sleep(random.uniform(0.5, 2.0))
