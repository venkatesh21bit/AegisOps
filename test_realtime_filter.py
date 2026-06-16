import os
from aegisops.integrations.otel_filter_engine import RealtimeTelemetryFilter

def test_realtime_filter():
    print("Testing RealtimeTelemetryFilter on generated logs...")
    filter = RealtimeTelemetryFilter(suppression_threshold=5, window_ms=1000.0)
    
    # Test DDOS
    log_path = r"C:\Users\91902\Documents\Other_Projects\AegisOps\logs\auth-service.log"
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            lines = [f.readline() for _ in range(50)] # get 50 lines to trigger suppression
            
            suppressed = False
            meta_event = False
            for line in lines:
                if not line.strip(): continue
                res = filter.process_frame(line)
                if res is None:
                    suppressed = True
                elif "[META-EVENT]" in res:
                    meta_event = True
            
            if suppressed and meta_event:
                print("DDOS suppression test: PASS")
            else:
                print("DDOS suppression test: FAIL (meta_event:", meta_event, ", suppressed:", suppressed, ")")

    # Test DLP
    log_path = r"C:\Users\91902\Documents\Other_Projects\AegisOps\logs\tls-service.log"
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
            dlp_pass = False
            for line in lines:
                res = filter.process_frame(line)
                if res and "postgres://***:***@" in res:
                    dlp_pass = True
                if res and "AKIA***" in res:
                    dlp_pass = True
            
            if dlp_pass:
                print("DLP masking test: PASS")
            else:
                print("DLP masking test: FAIL")

if __name__ == "__main__":
    test_realtime_filter()
