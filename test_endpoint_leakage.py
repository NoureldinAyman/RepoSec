from endpoint_extractors import extract_endpoints
from endpoint_severity import severity_for_url, severity_for_ip, severity_for_host


def test_basic_extraction_and_severity():
    text = """
    Public URL: https://example.com/docs
    Internal host: http://admin.corp.local/login
    Private IP: 192.168.1.10
    Metadata: http://169.254.169.254/latest/meta-data/
    Query token: https://api.example.com/v1?token=abc123
    """

    hits = extract_endpoints(text)

    # Extraction checks
    assert "https://example.com/docs" in hits["urls"]
    assert "http://admin.corp.local/login" in hits["urls"]
    assert "192.168.1.10" in hits["ipv4"]
    assert "169.254.169.254" in hits["ipv4"]
    assert "admin.corp.local" in hits["internal_hosts"]

    # Severity checks
    sev, _ = severity_for_url("https://example.com/docs")
    assert sev == "LOW"

    sev, _ = severity_for_host("admin.corp.local")
    assert sev == "MEDIUM"

    sev, _ = severity_for_ip("192.168.1.10")
    assert sev == "MEDIUM"

    sev, _ = severity_for_url("http://169.254.169.254/latest/meta-data/")
    assert sev == "HIGH"

    sev, _ = severity_for_url("https://api.example.com/v1?token=abc123")
    assert sev == "HIGH"


if __name__ == "__main__":
    test_basic_extraction_and_severity()
    print("OK")


# python test_endpoint_leakage.py
