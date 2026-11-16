#include "gateway_sdk/client.hpp"
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <regex>

namespace gateway::sdk {
static std::string hex(const unsigned char *value,size_t size){
    const char *digits="0123456789abcdef";std::string result;result.reserve(size*2);
    for(size_t i=0;i<size;++i){result+=digits[value[i]>>4];result+=digits[value[i]&15];}return result;
}
static std::string derived_key(const std::string& secret,const std::string& context){
    unsigned char out[EVP_MAX_MD_SIZE];unsigned size=0;
    if(!HMAC(EVP_sha256(),secret.data(),secret.size(),reinterpret_cast<const unsigned char *>(context.data()),context.size(),out,&size))throw std::runtime_error("HMAC failed");
    return hex(out,size);
}
static std::string origin(std::string host){
    if(host.find("://")==std::string::npos)host="https://"+host;
    for(unsigned char c:host)if(c<=32||c==127)throw std::invalid_argument("Invalid gateway host");
    std::unique_ptr<CURLU,decltype(&curl_url_cleanup)> url(curl_url(),curl_url_cleanup);
    if(!url||curl_url_set(url.get(),CURLUPART_URL,host.c_str(),0)!=CURLUE_OK)throw std::invalid_argument("Invalid gateway host");
    auto part=[&](CURLUPart field){char *value=nullptr;std::string result;if(curl_url_get(url.get(),field,&value,0)==CURLUE_OK){result=value;curl_free(value);}return result;};
    if(part(CURLUPART_SCHEME)!="https"||part(CURLUPART_HOST).empty()||part(CURLUPART_PATH)!="/"||
       !part(CURLUPART_USER).empty()||!part(CURLUPART_PASSWORD).empty()||!part(CURLUPART_QUERY).empty()||!part(CURLUPART_FRAGMENT).empty())throw std::invalid_argument("Gateway host must be an HTTPS origin");
    while(!host.empty()&&host.back()=='/')host.pop_back();
    std::transform(host.begin(),host.end(),host.begin(),[](unsigned char c){return std::tolower(c);});return host;
}
static bool valid_target(const Request& request){
    if(request.method.empty()||request.method.size()>32||!std::all_of(request.method.begin(),request.method.end(),[](char c){return c>='A'&&c<='Z';})||
       request.uri.empty()||request.uri.size()>4096||request.uri[0]!='/'||request.uri.rfind("//",0)==0||request.uri.rfind("/_gateway/",0)==0||request.uri.find_first_of("\\#")!=std::string::npos)return false;
    std::string decoded;
    auto digit=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
    for(size_t i=0;i<request.uri.size();++i){unsigned char c=request.uri[i];if(c<32||c==127)return false;
        if(c=='%'&&i+2<request.uri.size()&&digit(request.uri[i+1])>=0&&digit(request.uri[i+2])>=0){c=static_cast<unsigned char>(digit(request.uri[i+1])*16+digit(request.uri[i+2]));i+=2;}
        if(c<32||c==127||c=='\\')return false;
        decoded+=static_cast<char>(c);
    }return decoded.rfind("//",0)!=0;
}
struct Client::Impl {
    ClientOptions options;
    std::string gateway;
    struct Credentials {
        std::string appid,secret,login_secret;
        Verifier local,automatic;
        Credentials(std::string app,std::string key,Options config):appid(std::move(app)),secret(std::move(key)),
            login_secret(derived_key(secret,"gateway/sdk-login/v1")),local(config),automatic([&]{
                config.mode=Mode::Auto;
                if(config.verification_key.empty())config.verification_key=derived_key(secret,"gateway/verify-api/v1");
                return config;
            }()){}
    };
    mutable std::shared_ptr<const Credentials> cached;
    std::shared_ptr<const Credentials> credentials(const std::string& appid,const std::string& secret)const{
        static const std::regex pattern(R"(^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$)");
        if(!std::regex_match(appid,pattern))throw std::invalid_argument("Invalid appid");
        auto result=std::atomic_load(&cached);
        if(!result||result->appid!=appid||result->secret!=secret){
            Options config;config.secret=secret;config.issuer=gateway;config.audience=options.service_host;
            config.verification_key=options.verification_key;config.timeout=options.timeout;config.ca_file=options.ca_file;
            result=std::make_shared<Credentials>(appid,secret,config);std::atomic_store(&cached,result);
        }
        return result;
    }
    explicit Impl(ClientOptions config):options(std::move(config)),gateway(origin(options.gateway_host)){
        static const std::regex host(R"(^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z][a-z0-9-]*$)");
        if(options.service_host.size()>253||!std::regex_match(options.service_host,host))throw std::invalid_argument("Invalid service host");
    }
};
Client::Client(ClientOptions options):impl_(std::make_shared<Impl>(std::move(options))){}
CheckResult Client::checkCookie(const Request& request,const std::string& appid,const std::string& secret,bool redirect_on_failure,bool allow_online_fallback)const{
    CheckResult result;
    const auto credentials=impl_->credentials(appid,secret);
    const bool target_valid=valid_target(request);
    try{
        if(!target_valid)throw InvalidToken("invalid_request: invalid return target");
        bool binding=false;size_t pos=0;
        while(pos<request.cookie.size()){
            auto end=request.cookie.find(';',pos);if(end==std::string::npos)end=request.cookie.size();
            auto start=request.cookie.find_first_not_of(" \t",pos);
            const std::string prefix="__Host-gateway_binding=";
            if(start<end&&request.cookie.compare(start,prefix.size(),prefix)==0)binding=true;
            pos=end+1;
        }
        if(!binding)throw InvalidToken("cookie_empty: gateway binding cookie is missing");
        if(request.token.empty())throw InvalidToken("token_empty: X-Gateway-Token is missing");
        const auto& verifier=allow_online_fallback?credentials->automatic:credentials->local;
        result.identity=verifier.verify(request.token,request.cookie,request.method,request.uri,true);
        if(!result.identity->claims.contains("appid")||!result.identity->claims["appid"].is_string()||result.identity->claims["appid"]!=appid)
            throw InvalidToken("Token appid mismatch");
        result.result=CheckResultCode::Ok;result.allowed=true;result.status=200;return result;
    }catch(const VerificationUnavailable&){result.status=503;result.error="verification_unavailable: gateway verification is unavailable";}
     catch(const InvalidToken& error){
        std::string message=error.what();
        if(dynamic_cast<const UnsupportedVersion *>(&error)){
            result.status=426;result.error="unsupported_version: "+message;
        }else{
            result.status=target_valid?401:400;
            if(message.rfind("cookie_empty:",0)==0||message.rfind("token_empty:",0)==0||message.rfind("invalid_request:",0)==0)result.error=message;
            else if(message.find("cookie")!=std::string::npos&&message.find("token")==std::string::npos)result.error="cookie_invalid: "+message;
            else result.error="token_invalid: "+message;
        }
    }
    result.identity.reset();
    result.redictUrl=impl_->gateway+"/login?appid="+appid+"&token="+createLoginToken(appid,secret,target_valid?request.uri:"/",allow_online_fallback);
    if(redirect_on_failure){result.status=302;result.headers["Location"]=result.redictUrl;}
    return result;
}
std::string Client::createLoginToken(const std::string& appid,const std::string& secret,const std::string& uri,bool allow_online_fallback)const{
    if(!valid_target({"","","GET",uri}))throw std::invalid_argument("Invalid login return target");
    const auto credentials=impl_->credentials(appid,secret);
    unsigned char nonce[32];if(RAND_bytes(nonce,sizeof nonce)!=1)throw std::runtime_error("Random source unavailable");
    auto now=std::chrono::system_clock::now();
    return jwt::create().set_type("JWT").set_header_claim("gwv",jwt::claim(nlohmann::json(1)))
            .set_issuer(impl_->options.service_host).set_audience(impl_->gateway+"/login").set_issued_at(now)
            .set_not_before(now-std::chrono::seconds(2)).set_expires_at(now+std::chrono::seconds(300)).set_id(hex(nonce,sizeof nonce))
            .set_payload_claim("ver",jwt::claim(nlohmann::json(1))).set_payload_claim("type",jwt::claim(nlohmann::json("sdk_login")))
            .set_payload_claim("appid",jwt::claim(nlohmann::json(appid)))
            .set_payload_claim("return_url",jwt::claim(nlohmann::json("https://"+impl_->options.service_host+uri)))
            .set_payload_claim("sdk_version",jwt::claim(nlohmann::json(SDK_VERSION)))
            .set_payload_claim("token_versions",jwt::claim(nlohmann::json::array({1})))
            .set_payload_claim("cookie_versions",jwt::claim(nlohmann::json::array({1})))
            .set_payload_claim("allow_verify",jwt::claim(nlohmann::json(allow_online_fallback))).sign(jwt::algorithm::hs256(credentials->login_secret));
}
}
