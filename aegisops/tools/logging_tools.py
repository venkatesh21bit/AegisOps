# tools/logging_tools.py
import os
import re
from collections import Counter
from langchain_core.tools import tool

# Resolve log directory relative to the project root (AegisOps/logs/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOG_DIR = os.path.join(_PROJECT_ROOT, "logs")

def normalize_log_line(line: str) -> str:
    """Normalizes volatile variables inside log streams to collapse patterns."""
    # Strip standard ISO and common timestamps
    line = re.sub(r'\d{4}-\d{2}-\d{2}\s*\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', '', line)
    # Strip IPv4 addresses
    line = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', line)
    # Strip UUIDs
    line = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '[UUID]', line)
    # Strip naked isolated integers (such as ports or database IDs)
    line = re.sub(r'\b\d+\b', '[NUM]', line)
    return line.strip()

@tool
def get_logs(service_name: str, log_level: str = "error", k: int = 5) -> str:
    """Reads the last 500 lines of a service's log file, normalizes the text
    (stripping unique identifiers like IPs, UUIDs, and numbers so patterns collapse),
    ranks the error patterns by frequency, and returns the top-k highest occurrences."""
    log_path = os.path.join(_LOG_DIR, f"{service_name}.log")
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]  # Capture last 500 records

        # Filter log level dynamically and normalize text patterns
        filtered_normalized = []
        for line in lines:
            if log_level.upper() in line.upper():
                normalized = normalize_log_line(line)
                filtered_normalized.append(normalized)

        if not filtered_normalized:
            return f"No log entries found containing level '{log_level}'."

        # Calculate frequencies using Python's Counter
        counter = Counter(filtered_normalized)
        top_patterns = counter.most_common(k)

        # Format structured output as clear SRE evidence
        output = []
        for pattern, count in top_patterns:
            output.append(f"[{count} occurrences]: {pattern}")
        return "\n".join(output)

    except FileNotFoundError:
        return f"Operational Error: Log file not found at path: {log_path}"
    except Exception as e:
        return f"Log analysis aborted: {str(e)}"
