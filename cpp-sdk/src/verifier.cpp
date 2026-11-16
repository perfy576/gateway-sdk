#include "gateway_sdk/verifier.hpp"
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <algorithm>
#include <ctime>
#include <mutex>

namespace gateway::sdk {
using json=nlohmann::json;
static bool equal(const std::string& a,const std::string& b){return a.size()==b.size()&&CRYPTO_memcmp(a.data(),b.data(),a.size())==0;}
static std::string digest(const std::string& input){
    unsigned char data[SHA256_DIGEST_LENGTH];SHA256(reinterpret_cast<const unsigned char *>(input.data()),input.size(),data);
    const char *digits="0123456789abcdef";std::string result;result.reserve(64);
    for(auto c:data){result+=digits[c>>4];result+=digits[c&15];}return result;
}
static bool hex64(const std::string& value){return value.size()==64&&std::all_of(value.begin(),value.end(),[](char c){return(c>='0'&&c<='9')||(c>='a'&&c<='f');});}
static int version(const json& value){
    if(!value.is_number_integer()||value<1||value>2147483647)throw InvalidToken("Invalid protocol version");
    return value.get<int>();
}
static std::string cookie_value(const std::string& header){
    const std::string prefix="__Host-gateway_binding=";std::string value;bool found=false;size_t pos=0;
    while(pos<header.size()){
        auto end=header.find(';',pos);if(end==std::string::npos)end=header.size();auto start=header.find_first_not_of(" \t",pos);
        if(start<end&&header.compare(start,prefix.size(),prefix)==0){
            if(found)throw InvalidToken("Duplicate gateway binding cookie");
            found=true;value=header.substr(start+prefix.size(),end-start-prefix.size());
        }pos=end+1;
    }
    if(value.rfind("v1.",0)!=0||!hex64(value.substr(3)))throw InvalidToken("Missing or invalid gateway binding cookie");
    return value;
}
static void validate_url(const std::string& input){
    std::unique_ptr<CURLU,decltype(&curl_url_cleanup)> url(curl_url(),curl_url_cleanup);
    if(!url||curl_url_set(url.get(),CURLUPART_URL,input.c_str(),0)!=CURLUE_OK)throw std::invalid_argument("Invalid HTTPS verification URL");
    auto part=[&](CURLUPart field){char *value=nullptr;std::string result;if(curl_url_get(url.get(),field,&value,0)==CURLUE_OK){result=value;curl_free(value);}return result;};
    if(part(CURLUPART_SCHEME)!="https"||part(CURLUPART_HOST).empty()||!part(CURLUPART_USER).empty()||!part(CURLUPART_PASSWORD).empty()||
       !part(CURLUPART_QUERY).empty()||!part(CURLUPART_FRAGMENT).empty())throw std::invalid_argument("Issuer and verification URL must use HTTPS without credentials, query or fragment");
}
static void validate_input(const std::string& token,const std::string& cookie,const std::string& method,const std::string& uri){
    if(token.empty()||token.size()>16384||cookie.size()>32768||method.empty()||method.size()>32||uri.empty()||uri.size()>4096||uri[0]!='/'||uri.rfind("//",0)==0||uri.find_first_of("\\#")!=std::string::npos)
        throw InvalidToken("Invalid verification input");
    for(const auto *value:{&cookie,&method,&uri})for(unsigned char c:*value)if(c<32||c==127)throw InvalidToken("Invalid request characters");
}
static Identity identity(const json& claims,const std::string& source){
    for(const auto *key:{"sub","sid","username","display_name","role"})if(!claims.contains(key)||!claims[key].is_string())throw InvalidToken("Invalid identity claim");
    if(!claims.contains("authenticated")||!claims["authenticated"].is_boolean())throw InvalidToken("Invalid authentication claim");
    bool authenticated=claims["authenticated"];
    if(authenticated ? (claims["sub"].get<std::string>().empty()||!hex64(claims["sid"])) :
       (!claims["sub"].get<std::string>().empty()||!claims["sid"].get<std::string>().empty()||!claims["username"].get<std::string>().empty()||
        !claims["display_name"].get<std::string>().empty()||!claims["role"].get<std::string>().empty()))throw InvalidToken("Invalid session identity");
    return {authenticated,claims["sub"],claims["username"],claims["display_name"],claims["role"],version(claims.at("ver")),source,claims};
}
struct Verifier::Impl {
    Options options;
    decltype(jwt::verify()) jwt_verifier;
    explicit Impl(Options o):options(std::move(o)),jwt_verifier(jwt::verify().allow_algorithm(jwt::algorithm::hs256(options.secret))
        .with_issuer(options.issuer).with_audience(options.audience).leeway(3)){}
    json local(const std::string& token,const std::string& cookie,const std::string& method,const std::string& uri)const{
        auto decoded=jwt::decode(token);auto head=json::parse(decoded.get_header());
        if(version(head.at("gwv"))!=1)throw UnsupportedVersion("Unsupported gateway token version");
        if(head.value("alg",std::string())!="HS256"||head.value("typ",std::string())!="JWT")throw InvalidToken("Unsupported JWT algorithm or type");
        auto claims=json::parse(decoded.get_payload());
        for(const auto *key:{"iss","aud","sub","sid","username","display_name","role","type","cookie_name","cookie_sha256","request_method","request_uri_sha256"})
            if(!claims.contains(key)||!claims[key].is_string())throw InvalidToken("Missing string claim");
        for(const auto *key:{"iat","nbf","exp"})if(!claims.contains(key)||!claims[key].is_number_integer())throw InvalidToken("Missing integer claim");
        if(claims["iss"]!=options.issuer||claims["aud"]!=options.audience||version(claims.at("ver"))!=1)throw InvalidToken("Token scope or version mismatch");
        auto iat=claims["iat"].get<long long>(),exp=claims["exp"].get<long long>(),nbf=claims["nbf"].get<long long>(),now=static_cast<long long>(std::time(nullptr));
        if(iat<now-63||iat>now+3||exp<=now-3||exp>now+63||nbf<now-66||nbf>now+3||exp<=iat||exp-iat>60)throw InvalidToken("Invalid token lifetime");
        jwt_verifier.verify(decoded);
        if(version(claims.at("cookie_version"))!=1)throw UnsupportedVersion("Unsupported gateway cookie version");
        if(claims["type"]!="gateway_access"||claims["cookie_name"]!="__Host-gateway_binding")throw InvalidToken("Wrong token purpose");
        if(claims.contains("online_only")&&!claims["online_only"].is_boolean())throw InvalidToken("Invalid protocol negotiation flag");
        if(claims.value("online_only",false))throw UnsupportedVersion("Negotiated protocol requires online verification");
        if(claims["request_method"]!=method||!equal(claims["request_uri_sha256"],digest(uri)))throw InvalidToken("Token does not match this request");
        if(!equal(claims["cookie_sha256"],digest(cookie_value(cookie))))throw InvalidToken("Gateway cookie mismatch");
        return claims;
    }
    json online(const std::string& token,const std::string& cookie,const std::string& method,const std::string& uri)const{
        struct Handle{CURL *value=curl_easy_init();~Handle(){if(value)curl_easy_cleanup(value);}};
        thread_local Handle handle;if(!handle.value)throw VerificationUnavailable("Cannot initialize HTTPS client");
        auto *curl=handle.value;curl_easy_reset(curl);
        std::string body=json{{"token",token},{"cookie",cookie},{"method",method},{"uri",uri},{"audience",options.audience}}.dump(),response;
        curl_slist *raw=nullptr;raw=curl_slist_append(raw,"Content-Type: application/json");raw=curl_slist_append(raw,("Authorization: Bearer "+options.verification_key).c_str());
        std::unique_ptr<curl_slist,decltype(&curl_slist_free_all)> headers(raw,curl_slist_free_all);
        curl_easy_setopt(curl,CURLOPT_URL,options.verify_url.c_str());curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers.get());
        curl_easy_setopt(curl,CURLOPT_POST,1L);curl_easy_setopt(curl,CURLOPT_POSTFIELDS,body.data());curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,static_cast<long>(body.size()));
        curl_easy_setopt(curl,CURLOPT_TIMEOUT_MS,static_cast<long>(options.timeout.count()));curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT_MS,std::min(1000L,static_cast<long>(options.timeout.count())));
        curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1L);curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,2L);curl_easy_setopt(curl,CURLOPT_SSLVERSION,CURL_SSLVERSION_TLSv1_2);
#if LIBCURL_VERSION_NUM >= 0x075500
        curl_easy_setopt(curl,CURLOPT_PROTOCOLS_STR,"https");
#else
        curl_easy_setopt(curl,CURLOPT_PROTOCOLS,CURLPROTO_HTTPS);
#endif
        if(!options.ca_file.empty())curl_easy_setopt(curl,CURLOPT_CAINFO,options.ca_file.c_str());
        curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,+[](char *data,size_t size,size_t count,void *context)->size_t{
            size_t bytes=size*count;auto& output=*static_cast<std::string *>(context);if(bytes>65536-output.size())return 0;output.append(data,bytes);return bytes;
        });curl_easy_setopt(curl,CURLOPT_WRITEDATA,&response);
        if(curl_easy_perform(curl)!=CURLE_OK)throw VerificationUnavailable("Gateway HTTPS verification is unavailable");
        long status=0;curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
        if(status==400||status==401||status==403||status==404||status==422)throw InvalidToken("Gateway rejected token, cookie or verification credentials");
        if(status!=200)throw VerificationUnavailable("Gateway verification returned an unexpected HTTP status");
        try{
            auto value=json::parse(response);
            if(!value.contains("valid")||!value["valid"].is_boolean()||!value["valid"].get<bool>()||!value.contains("claims")||!value["claims"].is_object())throw VerificationUnavailable("Invalid verification response");
            for(const auto& [key,expected]:std::vector<std::pair<std::string,std::string>>{{"token_sha256",digest(token)},{"cookie_header_sha256",digest(cookie)},{"request_method",method},{"request_uri_sha256",digest(uri)}})
                if(!value.contains(key)||!value[key].is_string()||!equal(value[key],expected))throw VerificationUnavailable("Verification response does not match request");
            const auto& claims=value["claims"];
            if(claims.at("iss")!=options.issuer||claims.at("aud")!=options.audience||version(value.at("version"))!=version(claims.at("ver")))throw VerificationUnavailable("Verification response scope mismatch");
            return claims;
        }catch(const VerificationUnavailable&){throw;}catch(const std::exception&){throw VerificationUnavailable("Malformed gateway verification response");}
    }
};
Verifier::Verifier(Options options){
    static std::once_flag initialized;std::call_once(initialized,[]{if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK)throw std::runtime_error("Cannot initialize libcurl");});
    if(!hex64(options.secret)||options.audience.empty()||options.audience.size()>253)throw std::invalid_argument("Invalid signing secret or audience");
    if(options.verify_url.empty()){options.verify_url=options.issuer;while(!options.verify_url.empty()&&options.verify_url.back()=='/')options.verify_url.pop_back();options.verify_url+="/verify";}
    validate_url(options.issuer);validate_url(options.verify_url);
    if(options.mode!=Mode::Local&&!hex64(options.verification_key))throw std::invalid_argument("Online verification requires a separate verification key");
    if(options.timeout.count()<=0||options.timeout.count()>30000)throw std::invalid_argument("Timeout must be 1..30000 ms");
    impl_=std::make_shared<Impl>(std::move(options));
}
Identity Verifier::verify(const std::string& token,const std::string& cookie,const std::string& method,const std::string& uri,bool require_authenticated)const{
    validate_input(token,cookie,method,uri);
    try{
        json claims;std::string source="local";
        if(impl_->options.mode==Mode::Online){claims=impl_->online(token,cookie,method,uri);source="online";}
        else try{claims=impl_->local(token,cookie,method,uri);}catch(const UnsupportedVersion&){
            if(impl_->options.mode!=Mode::Auto)throw;
            claims=impl_->online(token,cookie,method,uri);source="online";
        }
        auto result=identity(claims,source);if(require_authenticated&&!result.authenticated)throw InvalidToken("Authenticated identity required");return result;
    }catch(const InvalidToken&){throw;}catch(const VerificationUnavailable&){throw;}catch(const std::exception&){throw InvalidToken("Invalid gateway token or cookie");}
}
}
