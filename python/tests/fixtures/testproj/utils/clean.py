import secrets


def make_token():
    return secrets.token_urlsafe(32)
