# Python 3 SDK

```bash
python3 -m pip install /data/code/gateway-sdk/python3-sdk
```

推荐初始化一个客户端并在请求处理函数中复用：

```python
import os
from gateway_sdk import GatewaySDK, Request, CheckResultCode

sdk = GatewaySDK(
    gateway_host="gateway.example.com",
    service_host="app.example.com",
    verification_key=os.environ["GATEWAY_VERIFICATION_KEY"],
)

def authenticate(headers, method, raw_request_uri):
    request = Request.from_headers(headers, method, raw_request_uri)
    result = sdk.checkCookie(request, appid="my-app", secret=os.environ["GATEWAY_TOKEN_SECRET"],
                             redirect_on_failure=True, allow_online_fallback=True)
    if result.result == CheckResultCode.Ok:
        return result.identity
    # The framework must return result.status and result.headers here.
    # result.error explains the failure; result.redictUrl is always populated.
    return result
```

`result` 只有 `Ok` 和 `redictionToLogin`。关闭 302 时失败仍返回 `redictUrl`，状态为对应的 400/401/426/503，且不设置 Location。错误原因仅在 `error`。`Request` 也可直接传入四个字段 `token`、`cookie`、`method`、`uri`。`check_cookie` 是同一函数的别名。

App 从后端调用登录接口时，使用同一客户端生成 Token：

```python
token = sdk.createLoginToken("my-app", os.environ["GATEWAY_TOKEN_SECRET"], "/docs?from=app")
payload = {"appid": "my-app", "username": username, "passwd": password, "token": token}
# POST payload as JSON to https://gateway.example.com/login using an HTTPS client.
# Only result == "Ok" provides a cookie for subsequent requests to app.example.com.
```

需要匿名身份或每次在线验证时，可以使用低层验证器。`auto` 在未知协议版本或协商要求在线验证时回退到 HTTPS `/verify`；默认 `local` 完全不联网：

```python
import os
from gateway_sdk import GatewayVerifier, InvalidToken, VerificationUnavailable

verifier = GatewayVerifier(
    secret=os.environ["GATEWAY_TOKEN_SECRET"],
    issuer="https://gateway.example.com",
    audience="app.example.com",
    mode="auto",
    verification_key=os.environ["GATEWAY_VERIFICATION_KEY"],
    timeout=3.0,
)

def authenticate(headers, method, raw_request_uri):
    try:
        return verifier.verify(
            token=headers.get("X-Gateway-Token", ""),
            cookie=headers.get("Cookie", ""),
            method=method,
            uri=raw_request_uri,
            require_authenticated=True,
        )
    except InvalidToken:
        # UnsupportedVersion is also an InvalidToken.
        raise PermissionError("Unauthorized")
    except VerificationUnavailable:
        # Return 503 to the caller; never continue with an unverified identity.
        raise RuntimeError("Authentication service unavailable")
```

返回 `Identity`，字段包括 `authenticated`、`user_id`、`username`、`display_name`、`role`、`token_version`、`verification`（local/online）和只读的 `claims`。允许匿名的接口可以不设置 `require_authenticated`，并根据返回的标志处理。

WSGI 的 `PATH_INFO` 通常已经解码，不能直接作为 `uri`；使用部署服务器提供的 `RAW_URI` / `REQUEST_URI`。ASGI 使用 `raw_path` 和原始 `query_string` 组合，并保留百分号编码。不要重新排序查询参数。HTTP 框架应拒绝重复的 `X-Gateway-Token` 请求头。

`verify_url` 默认是 `issuer + /verify`，可配置为另一条受信任的 HTTPS 地址；`ca_file` 可指定私有 CA。未知版本只影响解析和校验，不会自动下载或执行代码。

更多协议及在线校验细节见上级 [README](../README.md)。
