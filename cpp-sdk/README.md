# C++17 SDK

依赖 OpenSSL、libcurl、nlohmann/json，使用原生 GNU Make，自动获取固定提交的 jwt-cpp（`e71e0c2d584baff06925bbb3aad683f677e4d498`）。jwt-cpp 是纯头文件依赖，无需额外构建。

```bash
sudo apt-get install build-essential git pkg-config libssl-dev libcurl4-openssl-dev nlohmann-json3-dev
make -C /data/code/gateway-sdk -j2
make -C /data/code/gateway-sdk test
```

构建产物仍在 `/data/code/gateway-sdk/build/`：`libgateway_sdk.a`、`gateway-sdk-verify`，以及执行测试时生成的 `gateway-sdk-tests`。依赖源码默认保存在 SDK 根目录 `.deps/`。从 `cpp-sdk` 目录执行 `make` 同样可用。

业务项目的 Makefile 可直接链接静态库：

```make
.DEFAULT_GOAL := all
GATEWAY_SDK_ROOT ?= /data/code/gateway-sdk
GATEWAY_SDK_LIB := $(GATEWAY_SDK_ROOT)/build/libgateway_sdk.a
CPPFLAGS += -I$(GATEWAY_SDK_ROOT)/cpp-sdk/include
CXXFLAGS += -std=c++17

all: your_backend

your_backend: main.o $(GATEWAY_SDK_LIB)
	$(CXX) $(LDFLAGS) -o $@ $^ $(shell pkg-config --libs openssl libcurl) -pthread

$(GATEWAY_SDK_LIB):
	$(MAKE) -C $(GATEWAY_SDK_ROOT)
```

也可运行 `sudo make -C /data/code/gateway-sdk install` 安装头文件、静态库和 `gateway-sdk.pc`，然后在业务 Makefile 中使用 `pkg-config --cflags gateway-sdk` 与 `pkg-config --libs gateway-sdk`，链接 SDK 静态库和系统 OpenSSL、libcurl 动态库。安装支持 `PREFIX`、`DESTDIR`，SDK 公共头文件仍需系统提供 nlohmann/json。

`make clean` 仅清除构建产物，保留依赖源码。支持 `BUILD_DIR`、`DEPS_DIR`、`JWT_CPP_SRC`、`CXX`、`CPPFLAGS`、`CXXFLAGS`、`LDFLAGS`、`LDLIBS`；修改编译参数后先执行 `make clean`。离线环境可通过 `JWT_CPP_SRC` 指定相同固定提交的本地 Git 源码目录。

推荐每个服务创建一个客户端，允许多个请求线程并发复用。在线连接在每个线程中复用 libcurl handle。

```cpp
#include <gateway_sdk/client.hpp>

gateway::sdk::ClientOptions options;
options.gateway_host = "gateway.example.com";
options.service_host = "app.example.com";
options.verification_key = verification_key;
gateway::sdk::Client sdk(options);

gateway::sdk::Request request{token_header, cookie_header, method, raw_target};
auto result = sdk.checkCookie(request, "my-app", signing_secret, true, true);
if (result.result == gateway::sdk::CheckResultCode::Ok) {
    // Continue with result.identity.
} else {
    // Return result.status and result.headers through your HTTP framework.
    // result.error explains the failure; result.redictUrl is always populated.
}
```

最后两个参数分别控制失败是否返回 302、未知协议是否允许回退到 `/verify`。`result` 只有 `Ok` 和 `redictionToLogin`，具体原因在 `error`。关闭 302 时失败仍提供 `redictUrl`，不设置 Location。客户端不会自行写入 HTTP 响应。

App 后端生成接口登录 Token：

```cpp
auto token = sdk.createLoginToken("my-app", signing_secret, "/docs?from=app");
nlohmann::json body{{"appid", "my-app"}, {"username", username}, {"passwd", password}, {"token", token}};
// POST body as JSON to https://gateway.example.com/login using your HTTPS client.
// Forward the returned cookie to app.example.com only when result is "Ok".
```

需要匿名身份或每次在线验证时，可使用保留的低层验证器：

```cpp
#include <gateway_sdk/verifier.hpp>

gateway::sdk::Options options;
options.secret = signing_secret;
options.issuer = "https://gateway.example.com";
options.audience = "app.example.com";
options.mode = gateway::sdk::Mode::Auto;
options.verification_key = verification_key;
gateway::sdk::Verifier verifier(options);

// Inside a request handler. Read raw method/target before any URL rewriting.
try {
    auto identity = verifier.verify(token_header, cookie_header, method, raw_target, true);
    // Use identity.user_id, username, display_name, role.
} catch (const gateway::sdk::VerificationUnavailable&) {
    // Return 503; never continue as authenticated.
} catch (const gateway::sdk::InvalidToken&) {
    // Return 401. UnsupportedVersion derives from InvalidToken.
}
```

最后的 `true` 要求已登录身份；免登录接口可省略，根据 `identity.authenticated` 分支。返回结构包含 `token_version`、`verification`（local/online）和 `claims`。

可选配置：`verify_url`、`ca_file`、`timeout`（默认 3000ms）。默认 `Mode::Local`，未知版本拒绝；`Mode::Auto` 仅未知版本联网；`Mode::Online` 每次校验会话撤销状态。校验器不会加载 Token 指定的 URL，不跟随重定向，不允许 HTTP 或跳过 TLS 验证。

`build/gateway-sdk-verify` 是命令行示例，从 stdin 读取一个 JSON 请求对象，签名密钥和校验凭据从 `GATEWAY_TOKEN_SECRET`、`GATEWAY_VERIFICATION_KEY` 环境变量读取，成功输出身份 claims。适用于联调，不建议每次请求启动进程。

更多协议及在线校验细节见上级 [README](../README.md)。
