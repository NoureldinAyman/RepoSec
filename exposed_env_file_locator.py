import os
import subprocess

def audit_environment_security():
    env_file = ".env"
    
    # 1. Check if .env exists locally
    if not os.path.exists(env_file):
        print(f"[INFO] No {env_file} found. Ensure secrets are managed securely.")
        return

    # 2. Check if .env is ignored by Git
    # We use 'git check-ignore' to see if the file is properly excluded.
    try:
        result = subprocess.run(
            ["git", "check-ignore", env_file],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"[PASS] {env_file} is correctly ignored by Git.")
        else:
            print(f"[CRITICAL] {env_file} is NOT ignored by Git. Add it to .gitignore immediately!")
            
    except FileNotFoundError:
        print("[WARN] Git not found. Skipping git ignore check.")

    # 3. Check for public exposure risk (Example for a Flask app structure)
    # Ensure .env is not inside a 'static' or 'public' folder
    risky_dirs = ["static", "public", "assets", "frontend/build"]
    cwd = os.getcwd()
    
    for root, dirs, files in os.walk(cwd):
        if env_file in files:
            # Check if current root is a subdirectory of a risky dir
            for risky in risky_dirs:
                if os.path.join(cwd, risky) in root:
                     print(f"[CRITICAL] {env_file} detected in public directory: {root}")