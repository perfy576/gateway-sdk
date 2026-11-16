import hashlib
import hmac
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Optional

import jwt

BINDING_COOKIE = "__Host-gateway_binding"
_COOKIE_V1 = re.compile(r"v1\.[0-9a-f]{64}\Z")


class InvalidToken(ValueError):
    """The token, cookie, identity or request is invalid."""


class UnsupportedVersion(InvalidToken):
    """This SDK cannot verify the protocol version locally."""


class VerificationUnavailable(RuntimeError):
    """Online verification failed; the caller must deny access."""


@dataclass(frozen=True)
class Identity:
    authenticated: bool
    user_id: str
    username: str
    display_name: str
    role: str
    token_version: int
    verification: str
    claims: Mapping[str, Any]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _cookie(header: str) -> str:
    found = None
    for part in header.split(";"):
        name, separator, value = part.lstrip(" \t").partition("=")
        if separator and name == BINDING_COOKIE:
            if found is not None:
                raise InvalidToken("Duplicate gateway binding cookie")
            found = value
    if found is None or not _COOKIE_V1.fullmatch(found):
        raise InvalidToken("Missing or invalid v1 gateway binding cookie")
    return found


def _version(value: Any) -> int:
    if type(value) is not int or value < 1:
        raise InvalidToken("Missing or invalid protocol version")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GatewayVerifier:
    """Reuse per service. Modes: local, auto (unknown versions only), online."""

    SUPPORTED_TOKEN_VERSIONS = frozenset({1})
    SUPPORTED_COOKIE_VERSIONS = frozenset({1})

    def __init__(self, secret: str, issuer: str, audience: str, *, mode: str = "local",
                 verification_key: Optional[str] = None, verify_url: Optional[str] = None,
                 timeout: float = 3.0, ca_file: Optional[str] = None):
        if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-f]{64}", secret):
            raise ValueError("Use the original 64-character service signing secret")
        if mode not in ("local", "auto", "online"):
            raise ValueError("mode must be local, auto or online")
        if not isinstance(audience, str) or not audience or len(audience) > 253:
            raise ValueError("Invalid audience")
        for url in (issuer, verify_url or issuer.rstrip("/") + "/verify"):
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("Issuer and verification endpoint must be configured HTTPS URLs")
        if not 0 < timeout <= 30:
            raise ValueError("timeout must be in (0, 30]")
        if mode != "local" and (not isinstance(verification_key, str) or not re.fullmatch(r"[0-9a-f]{64}", verification_key)):
            raise ValueError("Online modes require the separate service verification key")
        self.secret, self.issuer, self.audience = secret, issuer, audience
        self.mode, self.verification_key = mode, verification_key
        self.verify_url, self.timeout = verify_url or issuer.rstrip("/") + "/verify", timeout
        self._opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def verify(self, token: str, cookie: str, method: str, uri: str, *, require_authenticated: bool = False) -> Identity:
        if not all(isinstance(value, str) for value in (token, cookie, method, uri)):
            raise InvalidToken("Verification inputs must be strings")
        if not token or len(token.encode("utf-8")) > 16384 or len(cookie.encode("utf-8")) > 32768:
            raise InvalidToken("Missing or oversized token/cookie")
        if not method or len(method) > 32 or not uri.startswith("/") or uri.startswith("//") or len(uri.encode("utf-8")) > 4096:
            raise InvalidToken("Invalid original request target")
        if any(ord(c) < 32 or ord(c) == 127 for c in method + uri + cookie) or "\\" in uri or "#" in uri:
            raise InvalidToken("Invalid request characters")
        try:
            if self.mode == "online":
                claims = self._online(token, cookie, method, uri)
                source = "online"
            else:
                try:
                    claims = self._local(token, cookie, method, uri)
                    source = "local"
                except UnsupportedVersion:
                    if self.mode != "auto":
                        raise
                    claims = self._online(token, cookie, method, uri)
                    source = "online"
            identity = self._identity(claims, source)
            if require_authenticated and not identity.authenticated:
                raise InvalidToken("An authenticated identity is required")
            return identity
        except (InvalidToken, VerificationUnavailable):
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, OverflowError) as error:
            raise InvalidToken("Invalid gateway token or cookie") from error

    def _local(self, token: str, cookie: str, method: str, uri: str) -> dict:
        header = jwt.get_unverified_header(token)
        version = _version(header.get("gwv"))
        if version not in self.SUPPORTED_TOKEN_VERSIONS:
            raise UnsupportedVersion("Unsupported gateway token version")
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise InvalidToken("Unsupported JWT algorithm or type")
        claims = jwt.decode(token, self.secret, algorithms=["HS256"], issuer=self.issuer,
                            audience=self.audience, leeway=3, options={"strict_aud": True, "require": [
                                "iss", "aud", "sub", "sid", "iat", "nbf", "exp", "ver", "cookie_version",
                                "type", "cookie_name", "cookie_sha256", "request_method", "request_uri_sha256",
                                "authenticated", "username", "display_name", "role"]})
        if _version(claims["ver"]) != version:
            raise InvalidToken("Token version mismatch")
        cookie_version = _version(claims["cookie_version"])
        if cookie_version not in self.SUPPORTED_COOKIE_VERSIONS:
            raise UnsupportedVersion("Unsupported gateway cookie version")
        if claims["type"] != "gateway_access" or claims["cookie_name"] != BINDING_COOKIE:
            raise InvalidToken("Wrong token purpose")
        if type(claims.get("online_only", False)) is not bool:
            raise InvalidToken("Invalid protocol negotiation flag")
        if claims.get("online_only", False):
            raise UnsupportedVersion("Negotiated protocol requires online verification")
        for key in ("iat", "nbf", "exp"):
            if type(claims[key]) is not int:
                raise InvalidToken("Invalid timestamp")
        now = time.time()
        if not 0 < claims["exp"] - claims["iat"] <= 60 or claims["iat"] < now - 63 or claims["exp"] > now + 63 or claims["nbf"] < now - 66:
            raise InvalidToken("Invalid token lifetime")
        if claims["request_method"] != method or not isinstance(claims["request_uri_sha256"], str) or not hmac.compare_digest(claims["request_uri_sha256"], _digest(uri)):
            raise InvalidToken("Token does not match this request")
        if not isinstance(claims["cookie_sha256"], str) or not hmac.compare_digest(claims["cookie_sha256"], _digest(_cookie(cookie))):
            raise InvalidToken("Gateway cookie mismatch")
        return claims

    def _online(self, token: str, cookie: str, method: str, uri: str) -> dict:
        data = json.dumps({"token": token, "cookie": cookie, "method": method, "uri": uri, "audience": self.audience}).encode("utf-8")
        request = urllib.request.Request(self.verify_url, data=data, method="POST", headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + self.verification_key})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                content = response.read(65537)
                if response.status != 200 or len(content) > 65536:
                    raise VerificationUnavailable("Invalid gateway verification response")
        except urllib.error.HTTPError as error:
            if error.code in (400, 401, 403, 404, 422):
                raise InvalidToken("Gateway rejected token, cookie or service credentials") from error
            raise VerificationUnavailable("Gateway verification returned HTTP " + str(error.code)) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise VerificationUnavailable("Gateway verification is unavailable") from error
        try:
            result = json.loads(content)
            expected = {"token_sha256": _digest(token), "cookie_header_sha256": _digest(cookie),
                        "request_method": method, "request_uri_sha256": _digest(uri)}
            if result.get("valid") is not True or not isinstance(result.get("claims"), dict):
                raise ValueError("Invalid verification result")
            for key, value in expected.items():
                if not isinstance(result.get(key), str) or not hmac.compare_digest(result[key], value):
                    raise ValueError("Verification response does not match request")
            claims = result["claims"]
            if claims.get("iss") != self.issuer or claims.get("aud") != self.audience or _version(result.get("version")) != _version(claims.get("ver")):
                raise ValueError("Verification response scope mismatch")
            return claims
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise VerificationUnavailable("Malformed gateway verification response") from error

    @staticmethod
    def _identity(claims: dict, source: str) -> Identity:
        for key in ("sub", "sid", "username", "display_name", "role"):
            if not isinstance(claims.get(key), str):
                raise InvalidToken("Invalid identity claim")
        authenticated = claims.get("authenticated")
        if type(authenticated) is not bool:
            raise InvalidToken("Invalid authentication claim")
        if authenticated and (not claims["sub"] or not re.fullmatch(r"[0-9a-f]{64}", claims["sid"])):
            raise InvalidToken("Invalid session identity")
        if not authenticated and (claims["sub"] or claims["sid"] or claims["username"] or claims["display_name"] or claims["role"]):
            raise InvalidToken("Anonymous token contains an identity")
        return Identity(authenticated, claims["sub"], claims["username"], claims["display_name"], claims["role"],
                        _version(claims.get("ver")), source, MappingProxyType(claims.copy()))
