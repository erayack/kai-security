import secrets


def generate_id() -> str:
    """Generate a random 24-character hex ID"""
    return secrets.token_hex(12)
