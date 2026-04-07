import unittest
from urllib.parse import parse_qs, urlparse

from app import (
    AppConfig,
    build_console_signin_url,
    decode_auth_state,
    extract_verified_email,
    issue_auth_state,
    sanitize_role_session_name,
)


class EmailExtractionTests(unittest.TestCase):
    def test_extracts_verified_email(self) -> None:
        claims = {"email": "user@example.com", "email_verified": True}
        self.assertEqual(extract_verified_email(claims), "user@example.com")

    def test_rejects_missing_email(self) -> None:
        with self.assertRaises(ValueError):
            extract_verified_email({"email_verified": True})

    def test_rejects_unverified_email(self) -> None:
        with self.assertRaises(ValueError):
            extract_verified_email({"email": "user@example.com", "email_verified": False})


class RoleSessionNameTests(unittest.TestCase):
    def test_preserves_valid_email_characters(self) -> None:
        self.assertEqual(sanitize_role_session_name("user.name+test@example.com"), "user.name+test@example.com")

    def test_replaces_invalid_characters(self) -> None:
        self.assertEqual(sanitize_role_session_name("user name@example.com"), "user-name@example.com")

    def test_truncates_to_64_characters(self) -> None:
        session_name = sanitize_role_session_name("very.long.email.address.with.many.sections.and.characters@example.com")
        self.assertLessEqual(len(session_name), 64)


class StateNonceTests(unittest.TestCase):
    def test_round_trips_signed_state(self) -> None:
        config = AppConfig(app_secret_key="unit-test-secret")
        state_token, nonce = issue_auth_state(config)
        payload = decode_auth_state(state_token, config)
        self.assertEqual(payload["nonce"], nonce)

    def test_rejects_tampered_state(self) -> None:
        config = AppConfig(app_secret_key="unit-test-secret")
        state_token, _ = issue_auth_state(config)
        tampered = state_token[:-1] + ("a" if state_token[-1] != "a" else "b")
        with self.assertRaises(ValueError):
            decode_auth_state(tampered, config)


class FederationUrlTests(unittest.TestCase):
    def test_builds_console_login_url(self) -> None:
        url = build_console_signin_url(
            "token123",
            "https://console.aws.amazon.com/",
            "https://broker.example.com",
        )
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        self.assertEqual(parsed.netloc, "signin.aws.amazon.com")
        self.assertEqual(params["Action"], ["login"])
        self.assertEqual(params["SigninToken"], ["token123"])
        self.assertEqual(params["Destination"], ["https://console.aws.amazon.com/"])
        self.assertEqual(params["Issuer"], ["https://broker.example.com"])


if __name__ == "__main__":
    unittest.main()
