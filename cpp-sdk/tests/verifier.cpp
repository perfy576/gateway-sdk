#include "gateway_sdk/verifier.hpp"
#include "gateway_sdk/client.hpp"
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <functional>
#include <iostream>

using json=nlohmann::json;
static std::string digest(const std::string& text){unsigned char d[32];SHA256(reinterpret_cast<const unsigned char *>(text.data()),text.size(),d);std::string result;const char *digits="0123456789abcdef";for(auto c:d){result+=digits[c>>4];result+=digits[c&15];}return result;}
static void require(bool condition){if(!condition)throw std::runtime_error("Assertion failed");}
static void rejects(const std::function<void()>& fn){bool rejected=false;try{fn();}catch(const gateway::sdk::InvalidToken&){rejected=true;}require(rejected);}
int main(){
    try{
        const std::string secret(64,'a'),binding="v1."+std::string(64,'b'),cookie="app=kept; __Host-gateway_binding="+binding;
        auto now=std::time(nullptr);
        json claims={{"iss","https://gateway.example.com"},{"aud","app.example.com"},{"sub","1"},{"sid",std::string(64,'c')},
            {"iat",now},{"nbf",now-2},{"exp",now+60},{"authenticated",true},{"appid","test.app"},{"username","alice"},{"display_name","Alice"},{"role","user"},
            {"ver",1},{"type","gateway_access"},{"cookie_version",1},{"cookie_name","__Host-gateway_binding"},{"cookie_sha256",digest(binding)},
            {"request_method","GET"},{"request_uri_sha256",digest("/docs?x=1")}};
        auto sign=[&](const json& value,int header_version=1){auto builder=jwt::create().set_type("JWT").set_header_claim("gwv",jwt::claim(json(header_version)));for(const auto& [key,v]:value.items())builder.set_payload_claim(key,jwt::claim(v));return builder.sign(jwt::algorithm::hs256(secret));};
        gateway::sdk::Options options;options.secret=secret;options.issuer="https://gateway.example.com";options.audience="app.example.com";
        gateway::sdk::Verifier verifier(options);auto token=sign(claims);
        auto verify=[&](const std::string& input){return verifier.verify(input,cookie,"GET","/docs?x=1");};
        require(verify(token).username=="alice");require(verify(token).verification=="local");
        rejects([&]{verifier.verify(token,"","GET","/docs?x=1");});
        rejects([&]{verifier.verify(token,"__Host-gateway_binding=v1."+std::string(64,'d'),"GET","/docs?x=1");});
        rejects([&]{verifier.verify(token,cookie+"; __Host-gateway_binding="+binding,"GET","/docs?x=1");});
        rejects([&]{verifier.verify(token,cookie,"POST","/docs?x=1");});rejects([&]{verifier.verify(token,cookie,"GET","/other");});
        auto altered=claims;altered["aud"]="wrong.example.com";rejects([&]{verify(sign(altered));});
        altered=claims;altered["exp"]=now-10;rejects([&]{verify(sign(altered));});
        altered=claims;altered["iat"]=now+20;altered["exp"]=now+80;rejects([&]{verify(sign(altered));});
        altered=claims;altered["exp"]=now+3600;rejects([&]{verify(sign(altered));});
        altered=claims;altered["type"]="login_request";rejects([&]{verify(sign(altered));});
        altered=claims;altered.erase("sid");rejects([&]{verify(sign(altered));});
        altered=claims;altered["ver"]=2;rejects([&]{verify(sign(altered));});
        altered=claims;altered["authenticated"]=false;altered["sub"]="";altered["sid"]="";altered["username"]="";altered["display_name"]="";altered["role"]="";
        auto anonymous=sign(altered);require(!verify(anonymous).authenticated);rejects([&]{verifier.verify(anonymous,cookie,"GET","/docs?x=1",true);});
        bool unsupported=false;try{verify(sign(claims,2));}catch(const gateway::sdk::UnsupportedVersion&){unsupported=true;}require(unsupported);
        options.mode=gateway::sdk::Mode::Auto;options.verification_key=std::string(64,'e');options.verify_url="https://127.0.0.1:1/verify";
        options.timeout=std::chrono::milliseconds(100);gateway::sdk::Verifier automatic(options);
        auto invalid=token;invalid.back()=invalid.back()=='a'?'b':'a';
        rejects([&]{automatic.verify(invalid,cookie,"GET","/docs?x=1");});
        bool unavailable=false;try{automatic.verify(sign(claims,2),cookie,"GET","/docs?x=1");}catch(const gateway::sdk::VerificationUnavailable&){unavailable=true;}require(unavailable);
        gateway::sdk::ClientOptions config;config.gateway_host="gateway.example.com";config.service_host="app.example.com";
        gateway::sdk::Client client(config);
        gateway::sdk::Request request{token,cookie,"GET","/docs?x=1"};
        auto result=client.checkCookie(request,"test.app",secret);require(result.result==gateway::sdk::CheckResultCode::Ok);
        require(result.allowed&&result.status==200&&result.error.empty()&&result.redictUrl.empty());
        require(result.identity&&result.identity->username=="alice");
        auto check_login=[&](const gateway::sdk::CheckResult& failure,const std::string& target){
            require(failure.result==gateway::sdk::CheckResultCode::redictionToLogin&&!failure.allowed&&!failure.error.empty());
            const std::string prefix="https://gateway.example.com/login?appid=test.app&token=";
            require(failure.redictUrl.rfind(prefix,0)==0);
            const std::string context="gateway/sdk-login/v1";unsigned char hash[32];unsigned size=0;
            require(HMAC(EVP_sha256(),secret.data(),secret.size(),reinterpret_cast<const unsigned char *>(context.data()),context.size(),hash,&size)!=nullptr);
            std::string key;const char *digits="0123456789abcdef";for(unsigned i=0;i<size;++i){key+=digits[hash[i]>>4];key+=digits[hash[i]&15];}
            auto decoded=jwt::decode(failure.redictUrl.substr(prefix.size()));
            jwt::verify().allow_algorithm(jwt::algorithm::hs256(key)).with_issuer("app.example.com").with_audience("https://gateway.example.com/login").verify(decoded);
            auto login=json::parse(decoded.get_payload());require(login["return_url"]==target&&login["sdk_version"]=="1.2.0");
            require(login["token_versions"]==json::array({1})&&login["cookie_versions"]==json::array({1}));
            require(login["exp"].get<long long>()-login["iat"].get<long long>()==300);
        };
        for(bool redirect:{false,true}){
            request.cookie="";result=client.checkCookie(request,"test.app",secret,redirect);
            check_login(result,"https://app.example.com/docs?x=1");require(result.error.rfind("cookie_empty:",0)==0);
            require(result.status==(redirect?302:401));require(result.headers.count("Location")==static_cast<size_t>(redirect));
            if(redirect)require(result.headers.at("Location")==result.redictUrl);
            request.cookie=cookie;request.token="";result=client.checkCookie(request,"test.app",secret,redirect);
            check_login(result,"https://app.example.com/docs?x=1");require(result.error.rfind("token_empty:",0)==0);
            request.token=token;request.cookie="__Host-gateway_binding=bad";result=client.checkCookie(request,"test.app",secret,redirect);
            check_login(result,"https://app.example.com/docs?x=1");require(result.error.rfind("cookie_invalid:",0)==0);
        }
        request.cookie=cookie;request.token=token;
        for(const auto *uri:{"//evil.invalid/","/%2f/evil.invalid","/\\evil.invalid","/%0d%0aLocation:x","/_gateway/callback"}){
            request.uri=uri;result=client.checkCookie(request,"test.app",secret,false);require(result.status==400&&result.error.rfind("invalid_request:",0)==0);
            check_login(result,"https://app.example.com/");
        }
        altered=claims;altered["online_only"]=true;request={sign(altered),cookie,"GET","/docs?x=1"};
        result=client.checkCookie(request,"test.app",secret,false);require(result.status==426&&result.error.rfind("unsupported_version:",0)==0);
        check_login(result,"https://app.example.com/docs?x=1");
        config.gateway_host="https://127.0.0.1:1";config.verification_key=std::string(64,'e');config.timeout=std::chrono::milliseconds(100);
        gateway::sdk::Client offline(config);request.token=sign(claims,2);
        result=offline.checkCookie(request,"test.app",secret,false,true);require(result.result==gateway::sdk::CheckResultCode::redictionToLogin);
        require(result.status==503&&result.error.rfind("verification_unavailable:",0)==0&&!result.redictUrl.empty());
        result=offline.checkCookie(request,"test.app",secret,true,true);require(result.status==302&&result.headers.at("Location")==result.redictUrl);
        request={token,cookie,"GET","/docs?x=1"};
        result=client.checkCookie(request,"other-app",secret,false);
        require(result.result==gateway::sdk::CheckResultCode::redictionToLogin&&!result.identity&&result.error.find("appid")!=std::string::npos);
        auto login=jwt::decode(client.createLoginToken("custom_App.1",secret,"/docs?x=1"));
        require(json::parse(login.get_payload())["appid"]=="custom_App.1");
        bool invalid_app=false;try{client.createLoginToken("bad app",secret);}catch(const std::invalid_argument&){invalid_app=true;}require(invalid_app);
        std::cout<<"C++ SDK security checks passed: versions, signature, request and cookie binding, duplicate cookie, expiry, identity, no downgrade on tamper and network fail-closed.\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
