"""
app.py

A minimal Flask application demonstrating the use of itsdangerous for token
generation and validation.
"""

from itsdangerous import URLSafeTimedSerializer

SECRET_KEY = "supersecret"

def create_token(data):
    """
    Generate a time-limited JSON Web token from a given dictionary.

    Args:
        data (dict): A dictionary of data to encode into the token.

    Returns:
        str: A string representing the encoded token that expires in 60 seconds.

    Example:
        >>> create_token({"user": "alice"})
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    """
    s = URLSafeTimedSerializer(SECRET_KEY)
    return s.dumps(data)

def verify_token(token):
    """
    Decode and validate a time-limited JSON Web token.

    Args:
        token (str): The token string to decode.

    Returns:
        dict: The original data encoded in the token if valid.

    Raises:
        itsdangerous.BadSignature: If the token is invalid or has been tampered with.
        itsdangerous.SignatureExpired: If the token has expired.

    Example:
        >>> verify_token('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')
        {'user': 'alice'}
    """
    s = URLSafeTimedSerializer(SECRET_KEY)
    return s.loads(token, max_age=60)
