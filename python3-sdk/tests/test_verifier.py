import hashlib
import json
import time
import unittest
from unittest.mock import patch

import jwt
from gateway_sdk import GatewayVerifier, InvalidToken, UnsupportedVersion, VerificationUnavailable


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.secret = "a" * 64
        self.binding = "v1." + "b" * 64
        self.cookie = "app=kept; __Host-gateway_binding=" + self.binding
        self.issuer = "https://gateway.example.com"
        self.audience = "app.example.com"
        now = int(time.time())
        self.claims = {"iss": self.issuer, "aud": self.audience, "sub": "1", "sid": "c" * 64,
                       "iat": now, "nbf": now - 2, "exp": now + 60, "authenticated": True,
                       "username": "alice", "display_name": "Alice", "role": "user", "ver": 1,
                       "type": "gateway_access", "cookie_version": 1, "cookie_name": "__Host-gateway_binding",
                       "cookie_sha256": hashlib.sha256(self.binding.encode()).hexdigest(),
                       "request_method": "GET", "request_uri_sha256": hashlib.sha256(b"/docs?x=1").hexdigest()}
        self.verifier = GatewayVerifier(self.secret, self.issuer, self.audience)

    def token(self, claims=None, version=1, algorithm="HS256"):
        return jwt.encode(self.claims if claims is None else claims, self.secret, algorithm=algorithm, headers={"gwv": version})

    def verify(self, token=None, cookie=None, **kwargs):
        return self.verifier.verify(token or self.token(), self.cookie if cookie is None else cookie, "GET", "/docs?x=1", **kwargs)

    def test_valid_identity(self):
        identity = self.verify()
        self.assertEqual(identity.username, "alice")
        self.assertEqual(identity.verification, "local")
        self.assertEqual(identity.token_version, 1)

    def test_cookie_binding(self):
        for cookie in ("", "__Host-gateway_binding=v1." + "d" * 64, self.cookie + "; " + self.cookie,
                       "__Host-gateway_binding=v2." + "b" * 64):
            with self.subTest(cookie=cookie), self.assertRaises(InvalidToken):
                self.verify(cookie=cookie)

    def test_claims_and_scope(self):
        now = int(time.time())
        for changes in ({"aud": "other.example.com"}, {"iss": "https://evil.invalid"},
                        {"exp": now - 10}, {"iat": now + 20, "exp": now + 80},
                        {"nbf": now + 20}, {"exp": now + 3600}, {"request_method": "POST"},
                        {"request_uri_sha256": "0" * 64}, {"type": "login_request"},
                        {"cookie_sha256": "0" * 64}, {"ver": True}, {"cookie_version": True},
                        {"authenticated": "true"}, {"sid": ""}, {"aud": [self.audience]}):
            with self.subTest(changes=changes), self.assertRaises(InvalidToken):
                self.verify(self.token(dict(self.claims, **changes)))

    def test_missing_fields(self):
        for key in self.claims:
            claims = self.claims.copy()
            del claims[key]
            with self.subTest(key=key), self.assertRaises(InvalidToken):
                self.verify(self.token(claims))

    def test_anonymous(self):
        claims = dict(self.claims, authenticated=False, sub="", sid="", username="", display_name="", role="")
        token = self.token(claims)
        self.assertFalse(self.verify(token).authenticated)
        with self.assertRaises(InvalidToken):
            self.verify(token, require_authenticated=True)

    def test_unknown_versions(self):
        with self.assertRaises(UnsupportedVersion):
            self.verify(self.token(dict(self.claims, ver=2), version=2))
        with self.assertRaises(UnsupportedVersion):
            self.verify(self.token(dict(self.claims, cookie_version=2)))

    def test_no_fallback_on_tamper(self):
        verifier = GatewayVerifier(self.secret, self.issuer, self.audience, mode="auto", verification_key="d" * 64)
        with patch.object(verifier, "_online") as online:
            token = jwt.encode(self.claims, "e" * 64, algorithm="HS256", headers={"gwv": 1})
            with self.assertRaises(InvalidToken):
                verifier.verify(token, self.cookie, "GET", "/docs?x=1")
            with self.assertRaises(InvalidToken):
                verifier.verify(self.token(), "", "GET", "/docs?x=1")
            online.assert_not_called()

    def test_future_version_fallback(self):
        verifier = GatewayVerifier(self.secret, self.issuer, self.audience, mode="auto", verification_key="d" * 64)
        claims = dict(self.claims, ver=2)
        token = self.token(claims, version=2)
        with patch.object(verifier, "_online", return_value=claims) as online:
            identity = verifier.verify(token, self.cookie, "GET", "/docs?x=1")
            self.assertEqual(identity.token_version, 2)
            self.assertEqual(identity.verification, "online")
            online.assert_called_once()

    def test_online_failure_denies(self):
        verifier = GatewayVerifier(self.secret, self.issuer, self.audience, mode="auto", verification_key="d" * 64)
        with patch.object(verifier, "_online", side_effect=VerificationUnavailable("offline")):
            with self.assertRaises(VerificationUnavailable):
                verifier.verify(self.token(dict(self.claims, ver=2), version=2), self.cookie, "GET", "/docs?x=1")

    def test_negotiated_online_only(self):
        token = self.token(dict(self.claims, online_only=True))
        with self.assertRaises(UnsupportedVersion):
            self.verify(token)
        verifier = GatewayVerifier(self.secret, self.issuer, self.audience, mode="auto", verification_key="d" * 64)
        with patch.object(verifier, "_online", return_value=dict(self.claims, online_only=True)) as online:
            self.assertEqual(verifier.verify(token, self.cookie, "GET", "/docs?x=1").verification, "online")
            online.assert_called_once()
        with self.assertRaises(InvalidToken):
            self.verify(self.token(dict(self.claims, online_only="true")))

    def test_configuration(self):
        for options in ({"mode": "auto"}, {"verify_url": "http://gateway.example.com/verify"},
                        {"verify_url": "https://user:pass@gateway.example.com/verify"}, {"timeout": 0}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                GatewayVerifier(self.secret, self.issuer, self.audience, **options)


if __name__ == "__main__":
    unittest.main()
