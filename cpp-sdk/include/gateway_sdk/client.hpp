#pragma once
#include "verifier.hpp"
#include <map>
#include <optional>

namespace gateway::sdk {
struct ClientOptions {
    std::string gateway_host,service_host,verification_key,ca_file;
    std::chrono::milliseconds timeout{3000};
};
struct Request {
    std::string token,cookie,method,uri;
};
enum class CheckResultCode {Ok,redictionToLogin};
inline const char *resultName(CheckResultCode result){
    switch(result){
        case CheckResultCode::Ok:return "Ok";
        case CheckResultCode::redictionToLogin:return "redictionToLogin";
    }
    return "redictionToLogin";
}
struct CheckResult {
    CheckResultCode result=CheckResultCode::redictionToLogin;
    std::string error,redictUrl;
    bool allowed=false;
    int status=401;
    std::map<std::string,std::string> headers{{"Cache-Control","no-store"}};
    std::optional<Identity> identity;
};
class Client {
    struct Impl;
    std::shared_ptr<const Impl> impl_;
public:
    explicit Client(ClientOptions options);
    CheckResult checkCookie(const Request& request,const std::string& appid,const std::string& secret,
        bool redirect_on_failure=true,bool allow_online_fallback=false) const;
    std::string createLoginToken(const std::string& appid,const std::string& secret,const std::string& uri="/",
        bool allow_online_fallback=false) const;
};
}
