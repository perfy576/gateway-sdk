import hashlib
import hmac
import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Optional

import jwt

from .verifier import GatewayVerifier, Identity, InvalidToken, UnsupportedVersion, VerificationUnavailable

SDK_VERSION = "1.2.0"


@dataclass(frozen=True)
class Request:
    token: str
    cookie: str
    method: str
    uri: str

    @classmethod
    def from_headers(cls, headers: Mapping[str, str], method: str, uri: str):
        normalized = {}
        for key, value in headers.items():
            name = key.lower()
            if name in normalized and name in ("cookie", "x-gateway-token"):
                raise InvalidToken("Duplicate authentication header")
            normalized[name] = value
        return cls(normalized.get("x-gateway-token", ""), normalized.get("cookie", ""), method, uri)


class CheckResultCode(str, Enum):
    Ok = "Ok"
    redictionToLogin = "redictionToLogin"


@dataclass(frozen=True)
class CheckResult:
    result: CheckResultCode
    error: str = ""
    redictUrl: str = ""
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({"Cache-Control": "no-store"}))
    identity: Optional[Identity] = None
    status: int = 200

    @property
    def allowed(self):
        return self.result == CheckResultCode.Ok

def _origin(host: str) -> str:
    if not isinstance(host, str) or any(c.isspace() or ord(c) < 32 for c in host):
        raise ValueError("Invalid gateway host")
    parsed = urllib.parse.urlsplit(host if "://" in host else "https://" + host)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("gateway_host must be an HTTPS origin or hostname")
    return "https://" + parsed.netloc.lower()


def _valid_target(method: str, uri: str) -> bool:
    if not isinstance(method, str) or not isinstance(uri, str) or not re.fullmatch(r"[A-Z]{1,32}", method):
        return False
    if not uri.startswith("/") or uri.startswith("//") or len(uri.encode("utf-8")) > 4096:
        return False
    decoded = urllib.parse.unquote(uri)
    return not decoded.startswith("//") and all(ord(c) >= 32 and ord(c) != 127 and c != "\\" for c in uri + decoded) and "#" not in uri and not uri.startswith("/_gateway/")


class GatewaySDK:
    """Configure once; checkCookie is the request-facing entry point."""

    TOKEN_VERSIONS = (1,)
    COOKIE_VERSIONS = (1,)

    def __init__(self, gateway_host: str, service_host: str, *,
                 verification_key: Optional[str] = None, timeout: float = 3.0, ca_file: Optional[str] = None):
        self.gateway_host = _origin(gateway_host)
        if not isinstance(service_host, str) or len(service_host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z][a-z0-9-]*", service_host):
            raise ValueError("service_host must be the configured business hostname")
        self.service_host = service_host
        self._options = dict(timeout=timeout, ca_file=ca_file)
        self._verification_key = verification_key
        self._cached = None

    def _credentials(self, appid: str, secret: str):
        if not isinstance(appid, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", appid):
            raise ValueError("Invalid appid")
        if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-f]{64}", secret):
            raise ValueError("Invalid service secret")
        cached = self._cached
        if cached is None or cached[:2] != (appid, secret):
            local = GatewayVerifier(secret, self.gateway_host, self.service_host, **self._options)
            key = self._verification_key or hmac.new(secret.encode(), b"gateway/verify-api/v1", hashlib.sha256).hexdigest()
            automatic = GatewayVerifier(secret, self.gateway_host, self.service_host, mode="auto", verification_key=key, **self._options)
            login_key = hmac.new(secret.encode(), b"gateway/sdk-login/v1", hashlib.sha256).hexdigest()
            cached = (appid, secret, local, automatic, login_key)
            self._cached = cached
        return cached

    def checkCookie(self, request: Request, appid: str, secret: str, redirect_on_failure: bool = True,
                    allow_online_fallback: bool = False) -> CheckResult:
        credentials = self._credentials(appid, secret)
        if type(redirect_on_failure) is not bool or type(allow_online_fallback) is not bool:
            raise ValueError("The redirect and online fallback flags must be booleans")
        if not isinstance(request, Request) or not _valid_target(request.method, request.uri) or not isinstance(request.token, str) or not isinstance(request.cookie, str):
            return self._failure("/", "invalid_request: invalid request fields or return target", 400, redirect_on_failure, allow_online_fallback, credentials)
        try:
            if not request.cookie.strip() or not any(part.lstrip(" \t").startswith("__Host-gateway_binding=") for part in request.cookie.split(";")):
                raise InvalidToken("cookie_empty: gateway binding cookie is missing")
            if not request.token:
                raise InvalidToken("token_empty: X-Gateway-Token is missing")
            verifier = credentials[3] if allow_online_fallback else credentials[2]
            identity = verifier.verify(request.token, request.cookie, request.method, request.uri, require_authenticated=True)
            if identity.claims.get("appid") != appid:
                raise InvalidToken("Token appid mismatch")
            return CheckResult(CheckResultCode.Ok, identity=identity)
        except VerificationUnavailable:
            return self._failure(request.uri, "verification_unavailable: gateway verification is unavailable", 503,
                                 redirect_on_failure, allow_online_fallback, credentials)
        except InvalidToken as error:
            if isinstance(error, UnsupportedVersion):
                reason = "unsupported_version: " + str(error)
                status = 426
            elif str(error).startswith(("cookie_empty:", "token_empty:")):
                reason, status = str(error), 401
            elif "cookie" in str(error).lower() and "token" not in str(error).lower():
                reason, status = "cookie_invalid: " + str(error), 401
            else:
                reason, status = "token_invalid: " + str(error), 401
            return self._failure(request.uri, reason, status, redirect_on_failure, allow_online_fallback, credentials)

    def createLoginToken(self, appid: str, secret: str, uri: str = "/", allow_online_fallback: bool = False) -> str:
        if not _valid_target("GET", uri) or type(allow_online_fallback) is not bool:
            raise ValueError("Invalid login target or fallback flag")
        return self._login_token(uri, allow_online_fallback, self._credentials(appid, secret))

    def _login_token(self, uri, allow_online_fallback, credentials):
        now = int(time.time())
        claims = {"iss": self.service_host, "aud": self.gateway_host + "/login", "iat": now, "appid": credentials[0],
                  "nbf": now - 2, "exp": now + 300, "jti": secrets.token_hex(32), "ver": 1, "type": "sdk_login",
                  "return_url": "https://" + self.service_host + uri, "sdk_version": SDK_VERSION,
                  "token_versions": list(self.TOKEN_VERSIONS), "cookie_versions": list(self.COOKIE_VERSIONS),
                  "allow_verify": allow_online_fallback}
        return jwt.encode(claims, credentials[4], algorithm="HS256", headers={"gwv": 1})

    def _failure(self, uri, reason, status, redirect_on_failure, allow_online_fallback, credentials):
        token = self._login_token(uri, allow_online_fallback, credentials)
        location = self.gateway_host + "/login?" + urllib.parse.urlencode({"appid": credentials[0], "token": token})
        headers = {"Cache-Control": "no-store"}
        if redirect_on_failure:
            headers["Location"] = location
        return CheckResult(CheckResultCode.redictionToLogin, reason, location, MappingProxyType(headers),
                           status=302 if redirect_on_failure else status)

    check_cookie = checkCookie
