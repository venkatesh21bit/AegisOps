"""
verify_connections.py
======================
Verifies all external connections using real credentials from .env.
Checks:
1. Gemini LLM (via langchain-google-genai)
2. Slack API (via slack_sdk)
3. Splunk HEC (via requests)
"""

import os
import sys
import asyncio
from dotenv import load_dotenv

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

load_dotenv()

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

def check_gemini():
    print(f"\n{Colors.CYAN}--- Testing Gemini LLM ---{Colors.RESET}")
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            print(f"{Colors.RED}[FAIL]{Colors.RESET} GOOGLE_API_KEY is not set.")
            return False
            
        llm = ChatGoogleGenerativeAI(
            model="gemini-3-flash-preview", 
            temperature=0, 
            max_retries=1,
            api_key=api_key
        )
        response = llm.invoke("Hello, are you connected? Respond with 'Yes'.")
        content_str = str(response.content)
        print(f"{Colors.GREEN}[OK]{Colors.RESET} Gemini Connected! Response: {content_str.strip()}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[FAIL]{Colors.RESET} Gemini Connection Error: {e}")
        return False

def check_slack():
    print(f"\n{Colors.CYAN}--- Testing Slack API ---{Colors.RESET}")
    try:
        import httpx
        
        token = os.getenv("SLACK_BOT_TOKEN")
        if not token:
            print(f"{Colors.RED}[FAIL]{Colors.RESET} SLACK_BOT_TOKEN is not set.")
            return False
            
        with httpx.Client(timeout=5.0) as client:
            response = client.post(
                "https://slack.com/api/auth.test",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
            )
            result = response.json()
            if result.get("ok"):
                bot_user = result.get("user", "Unknown")
                team = result.get("team", "Unknown")
                print(f"{Colors.GREEN}[OK]{Colors.RESET} Slack Connected! Authenticated as '{bot_user}' on team '{team}'.")
                return True
            else:
                print(f"{Colors.RED}[FAIL]{Colors.RESET} Slack Auth Error: {result.get('error')}")
                return False
    except Exception as e:
        print(f"{Colors.RED}[FAIL]{Colors.RESET} Slack Connection Error: {e}")
        return False

def check_splunk_hec():
    print(f"\n{Colors.CYAN}--- Testing Splunk HEC ---{Colors.RESET}")
    try:
        import requests
        host = os.getenv("SPLUNK_HOST", "localhost")
        port = os.getenv("SPLUNK_PORT", "8088")
        token = os.getenv("SPLUNK_HEC_TOKEN")
        
        if not token:
            print(f"{Colors.RED}[FAIL]{Colors.RESET} SPLUNK_HEC_TOKEN is not set.")
            return False
            
        # Try both 8088 (standard HEC) and the SPLUNK_PORT if they differ
        url = f"https://{host}:8088/services/collector/health"
        try:
            res = requests.get(url, verify=False, timeout=5)
            if res.status_code == 200:
                print(f"{Colors.GREEN}[OK]{Colors.RESET} Splunk HEC Health Check Passed (Port 8088).")
                return True
        except requests.RequestException:
            # Fallback to configured port
            url = f"https://{host}:{port}/services/collector/health"
            res = requests.get(url, verify=False, timeout=5)
            if res.status_code == 200:
                print(f"{Colors.GREEN}[OK]{Colors.RESET} Splunk HEC Health Check Passed (Port {port}).")
                return True
            else:
                 print(f"{Colors.RED}[FAIL]{Colors.RESET} Splunk HEC returned status: {res.status_code}")
                 return False
                 
    except Exception as e:
        print(f"{Colors.RED}[FAIL]{Colors.RESET} Splunk HEC Connection Error: {e}")
        return False

if __name__ == "__main__":
    print("==================================================")
    print("  VERIFYING REAL CREDENTIALS AND CONNECTIONS")
    print("==================================================")
    
    # Disable InsecureRequestWarning for local Splunk
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    gemini_ok = check_gemini()
    slack_ok = check_slack()
    splunk_ok = check_splunk_hec()
    
    print("\n==================================================")
    if gemini_ok and slack_ok and splunk_ok:
        print(f"{Colors.GREEN}ALL CONNECTIONS VERIFIED SUCCESSFULLY.{Colors.RESET}")
    else:
        print(f"{Colors.RED}SOME CONNECTIONS FAILED. CHECK LOGS ABOVE.{Colors.RESET}")
    print("==================================================")
