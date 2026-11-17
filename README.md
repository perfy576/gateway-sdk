# Gateway SDK

为 Gateway 提供 Python 3、C++17 和 Dart 后端接入，以及 Flutter 原生客户端。后端 SDK 校验 JWT 签名、协议版本、issuer、audience、时间、请求方法、原始路径及 Cookie 摘要，并返回已验证的用户身份。

- Python：[`python3-sdk`](python3-sdk/README.md)，Python >= 3.9，使用 PyJWT。
- C++：[`cpp-sdk`](cpp-sdk/README.md)，C++17，使用 jwt-cpp / OpenSSL / libcurl。
- Flutter / Dart：[`flutter-sdk`](flutter-sdk/README.md)，Dart >= 3.4，支持 Flutter 本地 path、Git 子目录和 Git submodule 引用；原生 App 使用不含 Secret 的 `GatewayClient`，可信 Dart 后端使用 `GatewaySDK`。

C++ / Python SDK 当前发布版本是 `1.2.0`，Flutter / Dart SDK 是 `1.3.0`（支持原生客户端包名和 User-Agent 上报），均支持 Token 协议 v1 和 Cookie 协议 v1。SDK 发布版本与协议版本独立。

## checkCookie

推荐入口是 `checkCookie(request, appid, secret, redirect_on_failure=true, allow_online_fallback=false)`。初始化一次网关 HTTPS host 和业务服务 host；每次调用显式传入服务 AppID、Secret，以及收到的 Token、完整 Cookie、HTTP 方法和原始 URI。相同凭据复用校验器，缓存只保留最近的一组凭据。AppID 由管理员自定义，为 1 至 64 位字母、数字、下划线、点或连字符，首位必须是字母或数字，区分大小写。

Secret 由网关生成，只保存当前一个；控制台可更换。在线校验凭据可显式配置，也可由 SDK 使用 Secret 按既定 HMAC 上下文派生。更换 Secret 后更新后端配置，旧 Secret 不再用于网关验证或签发。

返回结构的主要字段：

| 字段 | 说明 |
| --- | --- |
| `result` | 只有 `Ok`、`redictionToLogin` 两个枚举值。 |
| `error` | 成功为空；失败说明原因，如 `cookie_empty`、`cookie_invalid`、`token_empty`、`token_invalid`、`unsupported_version`、`verification_unavailable`。 |
| `redictUrl` | 成功为空；所有认证失败均返回签名登录 URL，保留这个字段拼写。 |

附带 `identity`、`allowed`、`status`、`headers` 方便接入。只允许 `Ok` 继续处理业务。`redirect_on_failure=true` 时失败返回 `status=302` 和 `Location=redictUrl`；关闭时仍提供 URL，但不设置 Location。SDK 不依赖 Web 框架，由业务框架应用返回的状态和响应头。参数或凭据配置错误会抛异常，应在初始化或集成时修正。

失败原因均在 `error`，包括在线校验不可用，不能据此放行。302 无法保留 POST 正文；提交型请求需要业务自行保存操作或重新提交。免登录接口需要允许匿名身份时，可使用下文低层 `GatewayVerifier` / `Verifier` API。

登录 URL 指向 `/login?appid=<AppID>&token=<signed JWT>`。签名保护 AppID、返回 URL、签发时间、5 分钟有效期、随机 jti、SDK 发布版本、支持的 Token/Cookie 协议和是否允许在线回退；不能修改 query 参数来切换服务或降级算法。该信封使用 `HMAC-SHA256(service_secret, "gateway/sdk-login/v1")` 的十六进制值作为 HS256 密钥，与访问 Token 的用途隔离。

网关先校验 SDK 请求，再跳转到业务域名 `/_gateway/start` 建立浏览器绑定，最后进入统一 `/login?appid=...&token=...`。返回目标固定在已配置的 HTTPS 业务域名。网关从双方支持的安全协议中选择；目前只有 v1。无兼容版本且不允许在线回退时返回 426；允许时使用当前协议并标记 `online_only`，SDK 必须通过 HTTPS `/verify` 验证。

## App 接口登录

三套后端 SDK 均提供 `createLoginToken`（参数命名见各 SDK 文档）。将返回的 Token 与同一 AppID、用户名和密码以 JSON 提交到 `POST /login`，无需浏览器 Cookie、CSRF 头或跳转：

```json
{"appid":"my-app","username":"alice","passwd":"<password>","token":"<signed-login-token>"}
```

成功为 HTTP 200：

```json
{"result":"Ok","retmsg":"登录成功","cookie":"__Host-gateway_session=v1.<session>; __Host-gateway_binding=v1.<binding>"}
```

失败为 HTTP 400/401/403/410/415/426/429/503 等，对象始终包含 `result:"Failed"`、原因 `retmsg`、空字符串 `cookie`。`POST /login` 的结果与 `checkCookie` 的两个枚举是不同接口，不要混用。

成功后把完整 `cookie` 值作为访问对应业务域名的 `Cookie` 请求头。它不能登录网关后台或其他服务。接口不会向网关域名设置浏览器 Cookie，也不会覆盖已有中央登录；有绑定 Cookie 摘要的后端 Token 仍由网关在实际转发时签发。若由业务后端代浏览器登录，应在业务域名分别设置两个 Cookie，使用 `Path=/; Secure; HttpOnly; SameSite=Lax`，不要通过前端脚本写入。

也可以直接向生成的 `/login?appid=...&token=...` URL 发 POST，JSON 正文只传 `username`、`passwd`。URL 与正文同时提供 AppID/Token 时必须完全一致。

SDK Token 和正常浏览器登录 URL 中的 Token 都可以调用该接口；当前进程内每个 Token 只能成功登录一次，并发提交只会有一次成功。失败可在有效期内重试，受登录限流约束。会话与已用 Token 标记只在内存，重启后会话失效、重放标记清空；SDK 自签 Token 仍受 5 分钟有效期约束。返回地址只影响浏览器回跳，不扩大 Cookie 的服务范围。Secret 仅放在可信服务端，移动客户端通过业务后端获取签名 Token，不应把 Secret 打包进应用。

## 协议

JWT 头包含 `gwv: 1`，payload 包含 `ver: 1`、`cookie_version: 1`、`type: "gateway_access"`，头和 payload 都受签名保护。算法固定为 HS256。每个服务有独立的 64 字符签名密钥，**原样作为 UTF-8 字符串使用，不做 hex 解码**。

所有网关生成的 Cookie 值使用 `v1.<64位小写十六进制随机数>`。浏览器会话为 `__Host-gateway_session`，服务端只保存摘要；后端不会收到会话凭据。额外的 `__Host-gateway_binding` 是独立绑定 Cookie，可转发给对应业务后端，JWT 中的 `cookie_sha256` 绑定它的完整值（包括 `v1.` 前缀）。登录态同时绑定这两个 Cookie，替换绑定 Cookie 会使登录态失效。绑定 Cookie 本身不能登录或创建会话。

SDK 接受从**业务后端收到的请求**读取的 `X-Gateway-Token` 和完整 `Cookie` 请求头。没有绑定 Cookie、Cookie 重复、摘要不匹配、方法不匹配或原始 URI 摘要不匹配，一律拒绝。第一条免登录请求没有绑定 Cookie 时，网关会为当前转发补齐 Cookie，并给浏览器设置 Cookie。

`method` 必须是原始 HTTP 方法，`uri` 必须是未经解码、排序或改写的原始 request-target（如 `/docs?a=1&b=2`）。普通应用 Cookie 不参与绑定，可以照常变化。SDK 不信任独立的用户名等请求头，只读取验证后的 claims。

## 校验模式

| 模式 | 行为 |
| --- | --- |
| `local` / `Mode::Local` | 默认。本地校验当前协议；未知版本抛出 UnsupportedVersion。 |
| `auto` / `Mode::Auto` | 本地校验；仅在 Token 或 Cookie 协议版本不支持时调用 `/verify`。 |
| `online` / `Mode::Online` | 每次调用 `/verify`，需要立即查询会话撤销状态时使用。 |

自动回退不是算法降级，也不会接纳无法验证的 Token：SDK 通过配置的 HTTPS 地址把 Token、Cookie、方法和 URI 交给支持该版本的网关，由网关完整验证。不能从未验证的 Token 里决定校验 URL。已支持版本的签名错误、过期、Cookie 不匹配等直接拒绝，不触发自动回退。当前网关只支持 v1，伪造的 v2 Token 即使触发回退，仍会被网关拒绝。

在线请求使用控制台钥匙弹窗里的**在线校验凭据**，不是签名密钥。这个独立凭据能调用当前服务的 `/verify`，不能签发 JWT。服务密钥轮换时，两者都需要更新。不要把任何密钥或凭据放到前端页面。

在线验证默认 3 秒超时，验证 HTTPS 证书，不跟随重定向，不允许 HTTP。支持配置私有 CA 文件。超时、网络故障、证书失败或响应异常抛出 VerificationUnavailable，业务应拒绝请求，可以返回 503；InvalidToken / UnsupportedVersion 返回 401。不会在联网失败后放行。

## 在线接口

```http
POST https://gateway.example.com/verify
Authorization: Bearer <在线校验凭据>
Content-Type: application/json
```

```json
{
  "audience": "app.example.com",
  "token": "<X-Gateway-Token>",
  "cookie": "app=value; __Host-gateway_binding=v1.<random>",
  "method": "GET",
  "uri": "/docs?a=1"
}
```

成功返回 200，包含 `valid: true`、协议 `version`、`verified_at`、已验证的 `claims` 以及与本次输入对应的 `token_sha256`、`cookie_header_sha256`、`request_method`、`request_uri_sha256`。失败返回 400/401/403，服务故障返回 5xx。在线验证还检查服务启用状态、当前用户权限、内存会话是否过期或撤销；匿名身份还会检查该路径当前是否免登录。SDK 验证响应与原请求及配置的服务匹配。

本地验证不查询内存状态，Token 签发后最多 60 秒有效，另允许 3 秒时钟偏差；退出登录后本地 Token 仍可能在剩余窗口内有效。需要即时撤销时选 online。免登录路径的身份为 `authenticated=false`，受保护接口应使用 `require_authenticated=True` / `true`。

Token 和绑定 Cookie 一起仍是短期 bearer 凭据，相同方法、相同 URI 在有效期内可能重放；请求正文未做摘要绑定。修改型业务需要自己的幂等和防重放机制。

## 测试

Python：`python -m unittest discover -s python3-sdk/tests -v`。

Flutter / Dart：在 `flutter-sdk` 下执行 `dart pub get`、`dart analyze`、`dart test`。`tests/flutter-integration.mjs` 验证原生客户端与三套后端 SDK 在真实网关的互通。

C++：在 SDK 根目录运行 `make -j2`、`make test`；也可直接使用 `make -C cpp-sdk`。构建、安装和清理均使用原生 GNU Make，详见 [C++ SDK 文档](cpp-sdk/README.md)。

`tests/fallback-https.mjs` 使用临时本地证书和模拟未来协议验证端，检查两套 SDK 的 v2 自动回退成功、TLS 信任、重定向拒绝和响应绑定。测试不向生产网关发布 v2 支持。默认使用当前工作区 `.venv` 和 `build/gateway-sdk-verify`。

真实部署联调脚本在 `/data/code/gateway/tools/sdk-integration.mjs`，临时创建服务，测试本地/在线校验、Cookie/Token 版本及篡改、会话撤销和凭据轮换，结束后删除测试服务。
