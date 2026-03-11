import requests
import threading
import time

TARGET_URL = "https://localhost:8443/api/"
NUM_THREADS = 20  
REQUESTS_PER_THREAD = 50  

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

stats = {"success": 0, "rate_limited": 0, "failed": 0}
stats_lock = threading.Lock()

def worker(thread_id):
    print(f"[*] Thread-{thread_id} starting...")
    for _ in range(REQUESTS_PER_THREAD):
        try:
            response = requests.get(TARGET_URL, verify=False, timeout=5)
            
            with stats_lock:
                if response.status_code == 200:
                    stats["success"] += 1
                elif response.status_code == 429:
                    stats["rate_limited"] += 1
                elif response.status_code in [502, 503, 504]:
                    stats["failed"] += 1
                else:
                    print(f"[?] Unexpected status code from Thread-{thread_id}: {response.status_code}")
                    
        except requests.exceptions.RequestException as e:
            with stats_lock:
                stats["failed"] += 1
                
    print(f"[*] Thread-{thread_id} finished.")

def run_dos_attack():
    print(f"[*] Starting DoS Simulation against {TARGET_URL}")
    print(f"[*] Workers: {NUM_THREADS}  |  Total Requests: {NUM_THREADS * REQUESTS_PER_THREAD}")
    print("-" * 50)
    
    start_time = time.time()
    threads = []
    
    for i in range(NUM_THREADS):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    end_time = time.time()
    
    print("-" * 50)
    print("[*] DoS Simulation Completed.")
    print(f"[*] Time Elapsed: {end_time - start_time:.2f} seconds")
    print("\n--- Final Statistics ---")
    print(f"[*] Successful Requests (200 OK): {stats['success']}")
    print(f"[*] Rate Limited (HTTP 429):      {stats['rate_limited']}")
    print(f"[*] Failed/Dropped Requests:      {stats['failed']}")
    
    if stats["rate_limited"] > 0:
         print("\n[+] System Resilience: Rate limiting successfully mitigated the attack.")
    elif stats["failed"] > 0 and stats["success"] == 0:
         print("\n[-] System Outage: Target service crashed or became unavailable.")
    else:
         print("\n[!] Warning: Server handled all traffic. No rate limiting observed.")

if __name__ == "__main__":
    run_dos_attack()
