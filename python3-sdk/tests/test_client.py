import hashlib
import hmac
import time
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import jwt
from gateway_sdk import GatewaySDK, Request, CheckResultCode, VerificationUnavailable


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.secret = "a" * 64
        self.client = GatewaySDK("gateway.example.com", "app.example.com", verification_key="d" * 64)
        self.binding = "v1." + "b" * 64
        self.cookie = "__Host-gateway_binding=" + self.binding
        now = int(time.time())
        self.claims = {"iss": "https://gateway.example.com", "aud": "app.example.com", "sub": "1", "sid": "c" * 64,
                       "iat": now, "nbf": now - 2, "exp": now + 60, "authenticated": True,
                       "appid": "test.app", "username": "alice", "display_name": "Alice", "role": "user", "ver": 1,
                       "type": "gateway_access", "cookie_version": 1, "cookie_name": "__Host-gateway_binding",
                       "cookie_sha256": hashlib.sha256(self.binding.encode()).hexdigest(),
                       "request_method": "GET", "request_uri_sha256": hashlib.sha256(b"/docs?x=1").hexdigest()}

    def check(self, request, *args):
        return self.client.checkCookie(request, "test.app", self.secret, *args)

    def request(self, **changes):
        values = dict(token=jwt.encode(self.claims, self.secret, algorithm="HS256", headers={"gwv": 1}),
                      cookie=self.cookie, method="GET", uri="/docs?x=1")
        return Request(**dict(values, **changes))

    def login_claims(self, result):
        parsed = urlsplit(result.redictUrl)
        self.assertEqual(parsed.netloc, "gateway.example.com")
        self.assertEqual(parsed.path, "/login")
        key = hmac.new(self.secret.encode(), b"gateway/sdk-login/v1", hashlib.sha256).hexdigest()
        return jwt.decode(parse_qs(parsed.query)["token"][0], key, algorithms=["HS256"],
                          issuer="app.example.com", audience="https://gateway.example.com/login")

    def test_only_two_results_and_success(self):
        self.assertEqual({member.value for member in CheckResultCode}, {"Ok", "redictionToLogin"})
        result = self.check(self.request())
        self.assertEqual(result.result, CheckResultCode.Ok)
        self.assertTrue(result.allowed)
        self.assertEqual((result.status, result.error, result.redictUrl), (200, "", ""))
        self.assertEqual(result.identity.username, "alice")

    def test_failures_always_include_login_url(self):
        for changes, reason in (({"cookie": ""}, "cookie_empty:"), ({"token": ""}, "token_empty:"),
                                ({"cookie": "__Host-gateway_binding=invalid"}, "cookie_invalid:"),
                                ({"token": "invalid"}, "token_invalid:")):
            for redirect in (True, False):
                with self.subTest(changes=changes, redirect=redirect):
                    result = self.check(self.request(**changes), redirect)
                    self.assertEqual(result.result, CheckResultCode.redictionToLogin)
                    self.assertFalse(result.allowed)
                    self.assertTrue(result.error.startswith(reason), result.error)
                    self.assertEqual(result.headers.get("Location"), result.redictUrl if redirect else None)
                    self.assertEqual(result.status, 302 if redirect else 401)
                    claims = self.login_claims(result)
                    self.assertEqual(claims["return_url"], "https://app.example.com/docs?x=1")
                    self.assertEqual(claims["sdk_version"], "1.2.0")
                    self.assertEqual(claims["token_versions"], [1])
                    self.assertEqual(claims["cookie_versions"], [1])
                    self.assertEqual(claims["exp"] - claims["iat"], 300)
                    self.assertFalse(claims["allow_verify"])

    def test_invalid_target_has_safe_return(self):
        for uri in ("//evil.invalid/", "/%2f/evil.invalid", "/\\evil.invalid", "/%0d%0aLocation:x", "/_gateway/callback"):
            result = self.check(self.request(uri=uri), False)
            self.assertTrue(result.error.startswith("invalid_request:"))
            self.assertEqual(result.status, 400)
            self.assertEqual(self.login_claims(result)["return_url"], "https://app.example.com/")

    def test_online_negotiation_and_failure(self):
        self.claims["online_only"] = True
        result = self.check(self.request(), False)
        self.assertEqual(result.result, CheckResultCode.redictionToLogin)
        self.assertTrue(result.error.startswith("unsupported_version:"))
        with patch.object(self.client._credentials("test.app", self.secret)[3], "_online", return_value=self.claims):
            result = self.check(self.request(), False, True)
            self.assertEqual(result.result, CheckResultCode.Ok)
            self.assertEqual(result.identity.verification, "online")
        with patch.object(self.client._credentials("test.app", self.secret)[3], "_online", side_effect=VerificationUnavailable("offline")):
            for redirect in (True, False):
                result = self.check(self.request(), redirect, True)
                self.assertEqual(result.result, CheckResultCode.redictionToLogin)
                self.assertTrue(result.error.startswith("verification_unavailable:"))
                self.assertEqual(result.status, 302 if redirect else 503)
                self.assertTrue(self.login_claims(result)["allow_verify"])

    def test_header_extraction(self):
        request = Request.from_headers({"Cookie": self.cookie, "X-GATEWAY-TOKEN": self.request().token}, "GET", "/docs?x=1")
        self.assertEqual(self.check(request).result, CheckResultCode.Ok)

    def test_appid_binding_and_cached_credentials(self):
        self.assertEqual(self.check(self.request()).result, CheckResultCode.Ok)
        cached = self.client._cached
        self.assertEqual(self.check(self.request()).result, CheckResultCode.Ok)
        self.assertIs(self.client._cached, cached)
        result = self.client.checkCookie(self.request(), "other-app", self.secret, False)
        self.assertEqual(result.result, CheckResultCode.redictionToLogin)
        self.assertIn("appid", result.error)
        self.assertEqual(parse_qs(urlsplit(result.redictUrl).query)["appid"], ["other-app"])
        self.assertEqual(self.login_claims(result)["appid"], "other-app")

    def test_create_login_token(self):
        token = self.client.createLoginToken("custom_App.1", self.secret, "/docs?x=1")
        key = hmac.new(self.secret.encode(), b"gateway/sdk-login/v1", hashlib.sha256).hexdigest()
        claims = jwt.decode(token, key, algorithms=["HS256"], audience="https://gateway.example.com/login")
        self.assertEqual(claims["appid"], "custom_App.1")
        self.assertEqual(claims["return_url"], "https://app.example.com/docs?x=1")
        for appid in ("", "bad app", "x" * 65, "/app"):
            with self.subTest(appid=appid), self.assertRaises(ValueError):
                self.client.createLoginToken(appid, self.secret)
        with self.assertRaises(ValueError):
            self.client.createLoginToken("test", "weak-secret")


if __name__ == "__main__":
    unittest.main()
