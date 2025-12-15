import hashlib
import os
import hmac
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

def verify_signature(payload_body, header_signature):
    """
    Verifies that the payload was sent by GitHub by validating the SHA256 signature.
    """
    if not WEBHOOK_SECRET:
        raise Exception("WEBHOOK_SECRET not configured")

    if not header_signature:
        return False

    # GitHub sends signature in format: sha256=hash_value
    sha_name, signature = header_signature.split('=')
    
    if sha_name != 'sha256':
        return False

    # Create local HMAC hash of the payload using the secret
    mac = hmac.new(
        WEBHOOK_SECRET.encode(), 
        msg=payload_body, 
        digestmod=hashlib.sha256
    )
    
    # Use compare_digest to prevent timing analysis attacks
    return hmac.compare_digest(mac.hexdigest(), signature)