from urllib.parse import urlparse, parse_qs


def classify_ipv4(ip):
    # Classify IPv4 by common security-relevant ranges.
    parts = ip.split(".")
    if len(parts) != 4:
        return "invalid"

    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return "invalid"

    if any(n < 0 or n > 255 for n in nums):
        return "invalid"

    a, b, c, d = nums

    if ip == "169.254.169.254":
        return "metadata"

    if a == 127:
        return "loopback"

    if a == 10:
        return "private"

    if a == 172 and 16 <= b <= 31:
        return "private"

    if a == 192 and b == 168:
        return "private"

    if a == 169 and b == 254:
        return "link-local"

    return "public"


def has_sensitive_query(url):
    # Very small heuristic for obvious credential leakage in query strings.
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    qs = parse_qs(parsed.query)
    keys = {k.lower() for k in qs.keys()}

    suspicious = {
        "token", "access_token", "auth", "authorization",
        "apikey", "api_key", "key",
        "secret", "password", "passwd",
        "signature", "sig",
    }
    return any(k in suspicious for k in keys)


def severity_for_ip(ip):
    # Convert IP classification into severity.
    cls = classify_ipv4(ip)

    if cls == "metadata":
        return "HIGH", "cloud-metadata-ip"
    if cls in ("private", "loopback", "link-local"):
        return "MEDIUM", cls
    if cls == "public":
        return "LOW", "public"
    return "LOW", "invalid"


def severity_for_host(host):
    # Internal hosts are usually MEDIUM by default.
    return "MEDIUM", "internal-hostname"


def severity_for_url(url):
    # URLs are LOW unless they point somewhere sensitive or leak creds in query.
    if has_sensitive_query(url):
        return "HIGH", "sensitive-query"

    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return "LOW", "unknown-host"

    # If hostname is actually an IP address, classify it.
    if host.replace(".", "").isdigit() and host.count(".") == 3:
        sev, reason = severity_for_ip(host)
        # If it's an internal IP behind a URL, bump to HIGH (more actionable).
        if sev == "MEDIUM":
            return "HIGH", f"url-to-{reason}"
        return sev, f"url-to-{reason}"

    return "LOW", "public-url"
