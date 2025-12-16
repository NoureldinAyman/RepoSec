from token_scanner import PATTERNS, mask


def find_hits(text):
    hits = []
    for line in text.splitlines():
        for name, sev, rx in PATTERNS:
            m = rx.search(line)
            if m:
                hits.append((name, sev, m.group(0)))
    return hits


def test_token_patterns_match():
    # NOTE: These are fake tokens crafted to match the regex shapes only.
    ghp_fake = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"  # 36 chars after ghp_
    hf_fake = "hf_abcdefghijklmnopqrstuv123456"            # 26 chars after hf_
    pat_fake = "github_pat_" + ("a" * 20)                  # 20 chars after prefix
    aws_fake = "AKIAABCDEFGHIJKLMNOP"                       # 16 chars after AKIA
    stripe_fake = "sk_test_" + ("a" * 16)                  # >=16 chars after sk_test_

    sample = f"""
    export HF_TOKEN={hf_fake}
    {ghp_fake}
    {pat_fake}
    AWS={aws_fake}
    stripe={stripe_fake}
    """

    hits = find_hits(sample)
    names = {h[0] for h in hits}

    assert "Hugging Face token" in names
    assert "GitHub token (ghp_)" in names
    assert "GitHub token (github_pat_)" in names
    assert "AWS Access Key ID" in names
    assert "Stripe secret key" in names


def test_masking():
    val = "hf_abcdefghijklmnopqrstuv123456"
    masked = mask(val)
    assert masked.startswith(val[:4])
    assert masked.endswith(val[-4:])
    assert "..." in masked


if __name__ == "__main__":
    test_token_patterns_match()
    test_masking()
    print("OK")
