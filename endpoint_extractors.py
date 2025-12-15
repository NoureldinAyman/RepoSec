import re

# URL: keep it simple (http/https only for now)
URL_RE = re.compile(r"\bhttps?://[^\s'\"<>()]+\b", re.IGNORECASE)

# IPv4: basic dotted quad. We'll validate ranges later.
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Internal-ish hostnames/domains: cheap heuristic keywords and common internal TLDs
HOST_RE = re.compile(
    r"\b[a-z0-9][a-z0-9\-_.]{1,253}\b",
    re.IGNORECASE,
)

INTERNAL_TLDS = (".local", ".internal", ".corp", ".lan")
INTERNAL_KEYWORDS = ("intranet", "corp", "internal", "admin", "staging")


def clean_match(s):
    # Remove common trailing junk from matches.
    return s.strip().strip(").,;:'\"[]{}<>")


def looks_internal_host(host):
    # Heuristic: internal TLDs or obvious internal keywords.
    h = host.lower()
    if any(h.endswith(tld) for tld in INTERNAL_TLDS):
        return True
    return any(k in h for k in INTERNAL_KEYWORDS)


def extract_endpoints(text):
    # Extract candidate URLs, IPv4 addresses, and internal-looking hostnames.
    urls = [clean_match(m.group(0)) for m in URL_RE.finditer(text)]
    ips = [clean_match(m.group(0)) for m in IPV4_RE.finditer(text)]

    hosts = []
    for m in HOST_RE.finditer(text):
        token = clean_match(m.group(0))

        # Skip stuff that is clearly not a hostname
        if "://" in token:
            continue
        if "." not in token:
            continue
        if token.count(".") < 1:
            continue

        if looks_internal_host(token):
            hosts.append(token)

    return {
        "urls": urls,
        "ipv4": ips,
        "internal_hosts": hosts,
    }


if __name__ == "__main__":
    demo = """
    API docs: https://api.example.com/v1/users
    Internal panel: http://admin.corp.local/login
    Private IP: 192.168.1.50 and metadata: 169.254.169.254
    Random text (hello). Also staging.internal.company
    """

    result = extract_endpoints(demo)
    print(result)
