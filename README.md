# Endpoint Leakage Scanner

This feature scans a repository’s **source code and text files** to detect **exposed endpoints** that may leak internal infrastructure details or sensitive URLs. It focuses on three common leakage types:

* **URLs** (e.g., `https://api.example.com`, `http://admin.corp.local`)
* **IPv4 addresses** (e.g., `192.168.1.10`, `169.254.169.254`)
* **Internal hostnames/domains** (e.g., `admin.corp.local`, `service.internal`)

### Why it matters

Exposed endpoints can help attackers map environments (internal networks, staging systems, admin panels) or identify high-value targets (cloud metadata services). This feature highlights those indicators early so they can be removed, masked, or moved into safer configuration.

---

## How it works

1. Traverses a user’s GitHub repositories (public repos) and walks the repository tree.
2. Downloads eligible text files (skipping common binaries and build/vendor folders).
3. Scans line-by-line to extract endpoint candidates and reports:
   * file path + line number
   * endpoint value (URL/IP/hostname)
   * severity + reason

---

## Severity model (simple)

* **HIGH**
  * Cloud metadata IP: `169.254.169.254`
  * URLs containing credential-like query parameters (e.g., `?token=...`, `?apikey=...`)
  * URLs pointing to internal IP ranges (private/loopback/link-local)
* **MEDIUM**
  * Private IPs (RFC1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  * Loopback: `127.0.0.0/8`
  * Link-local: `169.254.0.0/16`
  * Internal-looking hostnames (e.g., `.local`, `.internal`, `.corp`)
* **LOW**
  * Public URLs and public IPs without suspicious context

This is intentionally conservative and can be refined as the project evolves.

---

## How to run

### Requirements

```bash
pip install requests
```

### Run scanner

Scan each repo’s default branch:

```powershell
python endpoint_leakage_scanner.py <github_username>
```

Scan only the `main` branch:

```powershell
python endpoint_leakage_scanner.py <github_username> --main-only
```

### Optional: GitHub token (recommended)

If you hit rate limits, set a GitHub token to increase API limits:

```powershell
$env:GITHUB_TOKEN="YOUR_TOKEN_HERE"
```

---

## Output example

```
== user/repo (branch: main) ==
[MEDIUM] HOST user/repo:README.md:12  admin.corp.local  (internal-hostname)
[MEDIUM] IP   user/repo:config.yml:5  192.168.1.10      (private)
[HIGH]   URL  user/repo:app.py:44     http://169.254.169.254/latest/meta-data/ (url-to-metadata)

=== Summary ===
high=1 medium=2 low=0 total=3
```

The process exits with code **1** if any **HIGH** findings are detected (useful for CI later), otherwise  **0** .

---

## Files

* `endpoint_extractors.py` — regex extraction + normalization
* `endpoint_severity.py` — classification + severity scoring
* `endpoint_leakage_scanner.py` — traversal integration + reporting + summary
* `test_endpoint_leakage.py` — basic extraction/severity test
