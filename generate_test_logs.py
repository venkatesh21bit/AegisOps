import os
import shutil

# Make root logs dir
root_logs = r"C:\Users\91902\Documents\Other_Projects\AegisOps\logs"
os.makedirs(root_logs, exist_ok=True)

# Generate some logs there
with open(os.path.join(root_logs, "payment-service.log"), "w") as f:
    f.write("2026-06-14 10:00:00 ERROR: connection to upstream 10.0.1.42 timeout after 30s\n" * 15)
    f.write("2026-06-14 10:00:01 INFO: health check passed for payments system\n" * 5)
    f.write("2026-06-14 10:00:02 ERROR: connection to upstream 10.0.1.99 timeout after 30s\n" * 12)

