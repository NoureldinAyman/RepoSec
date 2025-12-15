# Secret / Token Scanner (Feature 1)

This feature scans repository files for **hardcoded secrets and access tokens** using a set of practical regex patterns (no entropy analysis). It is intended to catch common credential mistakes early (before code is merged or deployed).

### What it detects (examples)

The scanner looks for recognizable token formats such as:

* **Hugging Face tokens** : `hf_...`
* **GitHub tokens** : `ghp_...`, `github_pat_...`
* **GitLab tokens** : `glpat-...`
* **Slack tokens** : `xoxb-...`, `xoxp-...`, etc.
* **AWS Access Key IDs** : `AKIA...`
* **Google API keys** : `AIza...`
* **Stripe secret keys** : `sk_test_...`, `sk_live_...`
* **SendGrid keys** : `SG....`
* **Private key headers** : `-----BEGIN ... PRIVATE KEY-----`

The scanner prints masked values for safety (it does not print full secrets).

---

## Why it matters

Hardcoded credentials are one of the fastest ways to lose control of:

* cloud accounts,
* third-party services (Stripe, SendGrid, Slack),
* internal environments and admin tooling.

Even if a token is “test-only,” public exposure can still cause abuse (quota theft, account lockouts, reputation risk).

---

## How it works

1. Traverses a user’s GitHub repositories (public repos) and walks the repository tree.
2. Downloads eligible text files (skipping common binaries and build/vendor folders).
3. Scans line-by-line using regex patterns.
4. Reports findings with:
   * token type
   * severity
   * file path + line number
   * masked value
5. Prints an end-of-run summary and exits non-zero if high-risk secrets are found.

---

## Severity model

* **HIGH**
  * tokens that grant direct access (GitHub, Hugging Face, Stripe, SendGrid, Slack, npm, PyPI)
  * private key headers
* **MEDIUM**
  * identifiers that may indicate cloud credential usage (e.g., AWS Access Key ID)
  * API keys that may be environment-dependent (e.g., Google API keys)
* **LOW**
  * reserved for future tuning (not heavily used in the current rules)

Exit code policy:

* exits with code **1** if any **HIGH** finding is detected
* exits with **0** otherwise

---

## How to run

### Requirements

```bash
pip install requests
```

### Run scanner

Scan each repo’s default branch:

```powershell
python token_scanner.py <github_username>
```

Scan only the `main` branch:

```powershell
python token_scanner.py <github_username> --main-only
```

### Optional: GitHub token (recommended)

If you hit rate limits, set a GitHub token:

```powershell
$env:GITHUB_TOKEN="YOUR_TOKEN_HERE"
```

---

## Output example

```
== user/repo (branch: main) ==
[HIGH] GitHub token (ghp_) at user/repo:src/auth.py:12  value=ghp_...9Xk2
[MEDIUM] Google API key at user/repo:firebase-config.js:8  value=AIza...s0rM

=== Summary ===
repos:         6
files seen:    240
files scanned: 180
skipped:       filtered=40 large=5 timeout=10 conn=3 http=2
hits:          total=2 high=1 medium=1 low=0
```

---

## Files

* `traverse_user_repos.py` — GitHub traversal + branch selection + filtering
* `token_scanner.py` — token patterns, scanning, severity, summary
* `test_token_scanner.py` — basic regex/masking tests
