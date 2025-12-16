import sys
import os
import subprocess
import time

# --- Imports for local modules ---
try:
    from exposed_env_file_locator import audit_environment_security
except ImportError:
    audit_environment_security = None

try:
    from webhook_signature_validator import verify_signature
except ImportError:
    verify_signature = None

# --- ANSI Colors ---
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"

BANNER = f"""{CYAN}{BOLD}
    ____                  _____           
   / __ \___  ____  ____ / ___/___  _____
  / /_/ / _ \/ __ \/ __ \\__ \/ _ \/ ___/
 / _, _/  __/ /_/ / /_/ /__/ /  __/ /__  
/_/ |_|\___/ .___/\____/____/\___/\___/  
          /_/                            
      {RESET}{YELLOW}Security Toolkit CLI{RESET}
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print(BANNER)
    print(f"{BOLD}{'-' * 60}{RESET}")

def pause():
    input(f"\n{BOLD}Press Enter to return to menu...{RESET}")

# --- Feature 1: Endpoint Scanner ---
def run_endpoint_scanner():
    print(f"\n{GREEN}[ Feature 1: GitHub Endpoint Leakage Scanner ]{RESET}")
    username = input(f"Enter GitHub username to scan: ").strip()
    if not username: return

    choice = input(f"Scan {BOLD}'main'{RESET} branch only? (y/n) [default: y]: ").strip().lower()
    main_only = True if choice in ('', 'y', 'yes') else False

    cmd = [sys.executable, "endpoint_leakage_scanner.py", username]
    if main_only: cmd.append("--main-only")
    
    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
    pause()

# --- Feature 2: Token Scanner ---
def run_token_scanner():
    print(f"\n{GREEN}[ Feature 2: Hardcoded Secret & Token Scanner ]{RESET}")
    username = input(f"Enter GitHub username to scan: ").strip()
    if not username: return

    choice = input(f"Scan {BOLD}'main'{RESET} branch only? (y/n) [default: y]: ").strip().lower()
    main_only = True if choice in ('', 'y', 'yes') else False

    cmd = [sys.executable, "token_scanner.py", username]
    if main_only: cmd.append("--main-only")

    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
    pause()

# --- Feature 3: Env File Auditor ---
def run_env_auditor():
    print(f"\n{GREEN}[ Feature 3: Local .env Security Auditor ]{RESET}")
    print(f"Scanning directory: {os.getcwd()}")
    if audit_environment_security:
        audit_environment_security()
    else:
        print(f"{RED}Module 'exposed_env_file_locator' not found.{RESET}")
    pause()

# --- Feature 4: Dependency Scanner ---
def run_dependency_scanner():
    print(f"\n{GREEN}[ Feature 4: Dependency Vulnerability Scanner ]{RESET}")
    if not os.path.exists("requirements.txt"):
        print(f"{RED}Error: 'requirements.txt' not found.{RESET}")
        pause()
        return

    cmd = [sys.executable, "-m", "src.main", "scan-deps"]
    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
    pause()

# --- Feature 5: Webhook Validator ---
def run_webhook_validator():
    print(f"\n{GREEN}[ Feature 5: Webhook Signature Validator ]{RESET}")
    print("Verifies that a webhook payload matches its SHA256 signature header.\n")
    
    if not verify_signature:
        print(f"{RED}Module 'webhook_signature_validator' not found.{RESET}")
        pause()
        return

    # Check for secret
    secret = os.getenv("WEBHOOK_SECRET")
    if not secret:
        secret = input("Enter WEBHOOK_SECRET (input hidden): ").strip()
        os.environ["WEBHOOK_SECRET"] = secret

    payload = input("Enter Payload Body (string): ").strip()
    header = input("Enter Header Signature (e.g., sha256=...): ").strip()

    try:
        is_valid = verify_signature(payload.encode(), header)
        if is_valid:
            print(f"\n{GREEN}[PASS] Signature is VALID.{RESET}")
        else:
            print(f"\n{RED}[FAIL] Signature is INVALID.{RESET}")
    except Exception as e:
        print(f"{RED}Error validating: {e}{RESET}")
    pause()

# --- Feature 6: Commit History Scanner ---
def run_history_scanner():
    print(f"\n{GREEN}[ Feature 6: Insecure Commit History Scanner ]{RESET}")
    print("Scans git log for rewritten history or removed secrets.\n")
    
    # Placeholder: The script for this was missing in the dump, 
    # but the branch 'feature/insecure-commit-history' exists.
    print(f"{YELLOW}[INFO] This feature module is currently missing from the source files.{RESET}")
    print("Please merge 'feature/insecure-commit-history' or add 'history_scanner.py'.")
    pause()

def interactive_menu():
    while True:
        clear_screen()
        print_banner()
        print("Select a Security Tool:")
        print(f"  {CYAN}1.{RESET} Endpoint Leakage Scanner")
        print(f"  {CYAN}2.{RESET} Secret/Token Scanner")
        print(f"  {CYAN}3.{RESET} Local .env Auditor")
        print(f"  {CYAN}4.{RESET} Dependency Vuln Scanner (OSV)")
        print(f"  {CYAN}5.{RESET} Webhook Signature Validator")
        print(f"  {CYAN}6.{RESET} Insecure Commit History Scanner")
        print(f"  {CYAN}0.{RESET} Exit")
        
        choice = input(f"\n{BOLD}Selection [1-6, 0]:{RESET} ").strip()

        if choice == '1': run_endpoint_scanner()
        elif choice == '2': run_token_scanner()
        elif choice == '3': run_env_auditor()
        elif choice == '4': run_dependency_scanner()
        elif choice == '5': run_webhook_validator()
        elif choice == '6': run_history_scanner()
        elif choice == '0':
            print(f"\n{GREEN}Stay safe!{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}Invalid selection.{RESET}")
            time.sleep(0.5)

if __name__ == "__main__":
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print(f"\n\n{GREEN}Goodbye!{RESET}")
        sys.exit(0)
