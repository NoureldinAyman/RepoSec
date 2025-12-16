# RepoSec

RepoSec is a modular cybersecurity toolkit designed to scan Git repositories and local environments for security risks. It detects hardcoded secrets, exposed internal endpoints, vulnerable dependencies, and insecure configurations.

```text
    ____                  _____     
   / __ \___  ____  ____ / ___/___  _____
  / /_/ / _ \/ __ \/ __ \\__ \/ _ \/ ___/
 / _, _/  __/ /_/ / /_/ /__/ /  __/ /__  
/_/ |_|\___/ .___/\____/____/\___/\___/  
          /_/                      
      Security Toolkit CLI
```

## Features

RepoSec includes 6 core security modules:

1. **Endpoint Leakage Scanner**
   * Scans repository code for exposed internal IP addresses (e.g., `192.168.x.x`), internal domains (e.g., `.corp`, `.local`), and sensitive public URLs.
   * **Severity:** Categorizes findings as High (Metadata services), Medium (Internal IPs), or Low (Public URLs).
2. **Secret & Token Scanner**
   * Uses regex patterns to detect hardcoded credentials.
   * **Detects:** AWS Access Keys, Stripe Keys, GitHub Tokens, Slack Tokens, Private Keys, and more.
   * **Privacy:** Automatically masks the actual secret values in the output.
3. **Local .env Auditor**
   * Checks your *current* working directory.
   * Ensures `.env` files are present in `.gitignore`.
   * Detects if `.env` files are located in dangerous public folders (e.g., `public/`, `static/`).
4. **Dependency Vulnerability Scanner**
   * Parses `requirements.txt`.
   * Queries the **OSV.dev** open-source vulnerability database.
   * Reports known CVEs and security advisories for pinned versions.
5. **Webhook Signature Validator**
   * A utility to verify HMAC SHA256 signatures.
   * Useful for testing if your webhook validation logic matches expected payloads (e.g., from GitHub or Stripe).
6. **Insecure Commit History Scanner**
   * Scans the `git log` of a local repository.
   * Identifies secrets or sensitive data that were deleted from the current codebase but still exist in the project's commit history.

---

## Installation

1. **Clone the repository**
   **Bash**

   ```
   git clone https://github.com/NoureldinAyman/RepoSec.git
   cd RepoSec
   ```
2. **Create a Virtual Environment (Recommended)**

   * **Windows:**
     **Bash**

     ```
     python -m venv venv
     .\venv\Scripts\activate
     ```
   * **Mac/Linux:**
     **Bash**

     ```
     python3 -m venv venv
     source venv/bin/activate
     ```
3. **Install Dependencies**
   **Bash**

   ```
   pip install -r requirements.txt
   ```

---

## Usage

### Interactive CLI (Recommended)

The easiest way to use RepoSec is through the main menu, which provides access to all 6 tools.

**Bash**

```
python cli.py
```

Follow the on-screen prompts to select a tool, input target usernames/paths, or configure scan settings.

### Manual Execution (Advanced)

You can run individual modules directly if you need to integrate them into other scripts or CI/CD pipelines.

**Endpoint Scanner:**

**Bash**

```
python endpoint_leakage_scanner.py <username> [--main-only]
```

**Token Scanner:**

**Bash**

```
python token_scanner.py <username> [--main-only]
```

**Dependency Scanner:**

**Bash**

```
python -m src.main scan-deps
```

**Commit History Scanner:**

**Bash**

```
python commit_history_scanner.py <path_to_local_repo>
```

---

## Understanding the Output

When running scanners, you will see a summary line like this:

scanned=5 skipped=0 hits(H/M/L)=7/0/0

### 1. File Counts

* **Scanned:** The number of files successfully downloaded and analyzed.
* **Skipped:** The number of files ignored. Files are skipped if they are binary (images, executables), located in ignored directories (`node_modules`), or exceed the 2MB file size limit.

### 2. Severity Breakdown (H/M/L)

* **H (High):** Critical risk. These require immediate attention (e.g., AWS Secret Keys, Private Keys, Cloud Metadata IPs).
* **M (Medium):** Moderate risk. Potential exposure or sensitive identifiers (e.g., Internal Hostnames, API IDs).
* **L (Low):** Informational. Items that should be reviewed but may not be immediate threats (e.g., Public URLs).

---

## Configuration

### GitHub Rate Limits

If scanning large users or organizations, you may hit GitHub API rate limits. To avoid this, set a Personal Access Token:

* **Windows (PowerShell):** `$env:GITHUB_TOKEN="your_token"`
* **Mac/Linux:** `export GITHUB_TOKEN="your_token"`

### Webhook Validation

For the Webhook Validator tool, you can preset the secret environment variable:

* **Windows (PowerShell):** `$env:WEBHOOK_SECRET="your_secret_key"`
* **Mac/Linux:** `export WEBHOOK_SECRET="your_secret_key"`

---

## Disclaimer

This tool is intended for **educational purposes only**.
