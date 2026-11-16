# Gateway Flutter / Dart SDK

可直接放在 `gateway-sdk/flutter-sdk` 子目录。它是纯 Dart package，Flutter Android、iOS、macOS、Windows、Linux 项目均可引用，无需单独仓库或平台插件。当前版本 `1.2.0`，要求 Dart >= 3.4。

## 项目接入

开发时使用本地路径，在 Flutter 项目的 `pubspec.yaml` 添加：

```yaml
dependencies:
  gateway_sdk:
    path: ../gateway-sdk/flutter-sdk
```

也可以把整个 `gateway-sdk` 仓库作为 Git submodule 放到 Flutter 项目的 `vendor/gateway-sdk`，使用 `path: vendor/gateway-sdk/flutter-sdk`。

发布到你自己的 Git 仓库后，可直接引用仓库子目录，无需拆仓：

```yaml
dependencies:
  gateway_sdk:
    git:
      url: <gateway-sdk 仓库的真实 Git URL>
      ref: <固定的 tag 或 commit>
      path: flutter-sdk
```

上述 URL、ref 是占位符，目前此目录尚未配置 Git remote。执行 `flutter pub get` 后可导入 `package:gateway_sdk/gateway_sdk.dart`。Git 的 `path` 相对于仓库根目录，不是引用项目目录。

官方说明：[Git packages](https://dart.dev/tools/pub/dependencies#git-packages)、[Path packages](https://dart.dev/tools/pub/dependencies#path-packages)。

## Flutter 原生客户端

**客户端不配置 Secret。** Secret 可以签发服务身份，只能保存在可信后端，不能打包进 APK、IPA 或 Web 资源。

```dart
import 'package:gateway_sdk/gateway_sdk.dart';

final gateway = GatewayClient(
  gatewayHost: 'https://gateway.example.com',
  serviceHost: 'app.example.com',
  appid: 'my-app',
);

Future<bool> signIn(String username, String password) async {
  // 必须选择该服务下一个需要登录的路径；不会自动跟随 302。
  final challenge = await gateway.beginLogin('/private');
  final result = await gateway.login(
    username: username,
    passwd: password,
    token: challenge.token,
  );
  return result.allowed; // 失败原因为 result.retmsg。
}

Future<String> loadPrivateData() async {
  final response = await gateway.request('GET', '/private');
  if (response.statusCode != 200) {
    throw StateError('HTTP ${response.statusCode}');
  }
  return response.body;
}

// 不再使用时调用 gateway.close()。
```

`beginLogin` 访问固定业务域名，读取网关签发的 `/login?appid=...&token=...`。然后 `login` 调用 `POST /login`，仅在响应成功且 Cookie 格式有效时保存会话。也可直接传入可信业务后端提供的签名 Token，或使用 `parseLoginUrl` 解析已收到的登录 URL。登录 Token 有有效期且只能成功消费一次；重新登录应重新获取。

`request` 仅允许该服务上的相对绝对路径，如 `/api/items?a=1`；使用 HTTPS，不跟随重定向，不允许覆盖 Host/Cookie。支持字符串或字节正文、额外业务 headers。默认超时 10 秒，业务响应最多 16 MiB；登录和验证响应最多 64 KiB。网络异常会抛出异常，业务自行展示错误或重试，不会自动重复提交登录或修改请求。

登录失败返回 `LoginResult(result: 'Failed', retmsg: '原因', cookie: '')`；协议响应异常抛 `GatewayClientException`，传参错误抛 `ArgumentError`。`POST /login` 的 `Ok/Failed` 与后端 `checkCookie` 的两个枚举是不同接口。

默认会话仅在内存。需要持久化时用 `exportSession()` 获取数据，交给应用自己的系统安全存储；启动后通过 `restoreSession()` 恢复，恢复时检查 gateway、serviceHost、appid 和 Cookie 格式。不要写到日志或普通明文配置，也不要保存密码。

`hasSession` 只表示本地保存了 Cookie；网关重启、会话到期或权限变化后仍可能失效。收到业务 302 时可以用 `parseLoginUrl(response.headers['location'] ?? '')` 获取新挑战，业务 401 会清除本地会话。`clearSession()` 仅清除本地凭据，取消尚未完成的登录，不会撤销网关内存会话。

**Flutter Web：** 本包可被浏览器项目导入，但以上直接读写 Cookie 的客户端方法仅支持原生端。浏览器不能由 Dart 设置 `Cookie` 请求头或读取 HttpOnly Cookie；Web 项目应使用网关现有的浏览器跳转登录，由浏览器管理 Cookie，不能套用原生 App 登录代码。

## 可信 Dart 后端

与 C++ / Python 一致，提供签名校验和 `/verify` 降级；这部分独立导出，Secret 只放服务端：

```dart
import 'package:gateway_sdk/gateway_backend.dart';

final sdk = GatewaySDK(
  gatewayHost: 'https://gateway.example.com',
  serviceHost: 'app.example.com',
);

Future<CheckResult> authenticate(
    Map<String, String> headers, String method, String rawUri,
    String appid, String secret) {
  return sdk.checkCookie(
    GatewayRequest.fromHeaders(headers, method: method, uri: rawUri),
    appid,
    secret,
    redirectOnFailure: true,
    allowOnlineFallback: true,
  );
}
```

`result` 严格只有 `CheckResultCode.Ok`、`CheckResultCode.redictionToLogin`。原因在 `error`，跳转 URL 在 `redictUrl`，保留现有接口拼写。只在 `allowed == true` 时放行业务；失败时由框架应用 `status` 和 `headers`，SDK 不直接写 HTTP 响应。开启重定向时返回 302 和 Location；关闭时仍提供签名 URL，但不设置 Location。

`checkCookie` 要求已登录身份。低层 `verify(..., mode: VerificationMode.local/auto/online, requireAuthenticated: ...)` 可处理免登录路径的匿名身份。默认本地模式；自动模式仅对不支持的版本或网关协商的 `online_only` 调用 HTTPS `/verify`。已知版本的签名、Cookie、时间、方法和 URI 错误直接拒绝。在线失败不放行，响应必须与本次输入摘要、业务服务和 AppID 匹配。

`createLoginToken(appid, secret, uri: '/private', allowOnlineFallback: true)` 可供可信后端生成 App 登录 Token，兼容现有 C++、Python 和 `POST /login`。签名密钥原样按 UTF-8 使用，不做 hex 解码。低层协议、60 秒访问 Token、3 秒时钟偏差、即时撤销限制见[协议文档](../README.md)。

所有实例可注入 `package:http` 的 `Client`，便于连接池、系统可信私有 CA 和测试；外部注入的 Client 由调用方关闭。不要关闭证书验证。在线校验默认 3 秒超时，拒绝重定向。

## 验证

```bash
dart pub get
dart analyze
dart test
```

`../tests/flutter-integration.mjs` 用临时服务联调现有网关，覆盖原生登录、服务端签名登录、C++ / Python 交叉校验、本地及在线验证、会话隔离与篡改拒绝；测试结束删除临时服务。`tool/live_probe.dart` 是该测试的本机 TLS 路由适配器，不用于生产客户端。
