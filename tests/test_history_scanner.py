from src.features.commit_history.history_scanner import scan_text_for_secrets


def test_detects_aws_key():
    text = "AWS key: AKIA1234567890ABCDEF"
    findings = scan_text_for_secrets(text)
    assert any(rule == "AWS_ACCESS_KEY" for rule, _ in findings)


def test_detects_password_assignment():
    text = 'password = "supersecret123"'
    findings = scan_text_for_secrets(text)
    assert any(rule == "GENERIC_PASSWORD_ASSIGNMENT" for rule, _ in findings)
