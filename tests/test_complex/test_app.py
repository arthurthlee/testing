"""
Unit tests for the complex.app module.

These tests verify that the token generation and validation logic
behaves as expected under specific package versions of Flask and
itsdangerous.
"""

from complex.app import create_token, verify_token

def test_round_trip():
    """
    Test a full round-trip of token creation and verification.

    This test ensures that data passed into `create_token` can be
    serialized into a token and then successfully deserialized back
    into the original data structure using `verify_token`. The test
    validates both correctness of the encoding/decoding process and
    compatibility with dependency versions.

    Expected behavior:
        - A dictionary containing {"user": "alice"} is correctly
          embedded into the token.
        - After verification, the deserialized data matches the
          original dictionary.
    """
    data = {"user": "alice"}
    token = create_token(data)

    # On old versions: round-trip works fine
    loaded = verify_token(token)
    assert loaded["user"] == "alice"
