"""Read one request as JSON from stdin; credentials come from environment variables."""
import json
import os
import sys

from gateway_sdk import GatewaySDK, Request, GatewayVerifier, InvalidToken, UnsupportedVersion, VerificationUnavailable


def main():
    try:
        data = json.load(sys.stdin)
        if data.get("operation") in ("checkCookie", "createLoginToken"):
            sdk = GatewaySDK(data["gateway_host"], data["audience"],
                             verification_key=os.environ.get("GATEWAY_VERIFICATION_KEY"), ca_file=data.get("ca_file"),
                             timeout=data.get("timeout_ms", 3000) / 1000)
            if data["operation"] == "createLoginToken":
                print(json.dumps({"token": sdk.createLoginToken(data["appid"], os.environ["GATEWAY_TOKEN_SECRET"], data["uri"], data.get("allow_online_fallback", False))}))
                return 0
            result = sdk.checkCookie(Request(data.get("token", ""), data.get("cookie", ""), data["method"], data["uri"]),
                                     data["appid"], os.environ["GATEWAY_TOKEN_SECRET"],
                                     data.get("redirect_on_failure", True), data.get("allow_online_fallback", False))
            output = {"result": result.result.value, "redictUrl": result.redictUrl, "allowed": result.allowed,
                      "status": result.status, "headers": dict(result.headers), "error": result.error}
            if result.identity:
                output["claims"] = dict(result.identity.claims)
            print(json.dumps(output))
            return 0
        verifier = GatewayVerifier(os.environ["GATEWAY_TOKEN_SECRET"], data["issuer"], data["audience"],
                                   mode=data.get("mode", "local"), verification_key=os.environ.get("GATEWAY_VERIFICATION_KEY"),
                                   verify_url=data.get("verify_url"), ca_file=data.get("ca_file"),
                                   timeout=data.get("timeout_ms", 3000) / 1000)
        identity = verifier.verify(data["token"], data["cookie"], data["method"], data["uri"],
                                   require_authenticated=data.get("require_authenticated", False))
        print(json.dumps({"valid": True, "verification": identity.verification, "claims": dict(identity.claims)}))
        return 0
    except UnsupportedVersion:
        print("unsupported_version", file=sys.stderr)
        return 4
    except VerificationUnavailable:
        print("verification_unavailable", file=sys.stderr)
        return 3
    except (InvalidToken, ValueError, KeyError, TypeError):
        print("invalid_token_or_configuration", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
