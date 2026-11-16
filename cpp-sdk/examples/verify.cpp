#include "gateway_sdk/verifier.hpp"
#include "gateway_sdk/client.hpp"
#include <cstdlib>
#include <iostream>

int main(){
    try{
        const char *secret=std::getenv("GATEWAY_TOKEN_SECRET");if(!secret)throw std::invalid_argument("GATEWAY_TOKEN_SECRET is required");
        nlohmann::json input;std::cin>>input;
        if(input.value("operation",std::string())=="checkCookie"||input.value("operation",std::string())=="createLoginToken"){
            gateway::sdk::ClientOptions config;config.gateway_host=input.at("gateway_host");config.service_host=input.at("audience");
            const char *key=std::getenv("GATEWAY_VERIFICATION_KEY");if(key)config.verification_key=key;
            config.ca_file=input.value("ca_file",std::string());config.timeout=std::chrono::milliseconds(input.value("timeout_ms",3000));
            gateway::sdk::Client client(config);
            if(input.at("operation")=="createLoginToken"){
                std::cout<<nlohmann::json{{"token",client.createLoginToken(input.at("appid"),secret,input.at("uri"),input.value("allow_online_fallback",false))}}.dump()<<'\n';return 0;
            }
            gateway::sdk::Request request{input.value("token",std::string()),input.value("cookie",std::string()),input.at("method"),input.at("uri")};
            auto result=client.checkCookie(request,input.at("appid"),secret,input.value("redirect_on_failure",true),input.value("allow_online_fallback",false));
            nlohmann::json output={{"result",gateway::sdk::resultName(result.result)},{"redictUrl",result.redictUrl},
                {"allowed",result.allowed},{"status",result.status},{"headers",result.headers},{"error",result.error}};
            if(result.identity)output["claims"]=result.identity->claims;
            std::cout<<output.dump()<<'\n';return 0;
        }
        gateway::sdk::Options options;options.secret=secret;options.issuer=input.at("issuer");options.audience=input.at("audience");
        auto mode=input.value("mode",std::string("local"));
        if(mode=="auto")options.mode=gateway::sdk::Mode::Auto;else if(mode=="online")options.mode=gateway::sdk::Mode::Online;else if(mode!="local")throw std::invalid_argument("Unknown verification mode");
        const char *key=std::getenv("GATEWAY_VERIFICATION_KEY");if(key)options.verification_key=key;
        options.verify_url=input.value("verify_url",std::string());options.ca_file=input.value("ca_file",std::string());
        options.timeout=std::chrono::milliseconds(input.value("timeout_ms",3000));
        gateway::sdk::Verifier verifier(options);
        auto identity=verifier.verify(input.at("token"),input.at("cookie"),input.at("method"),input.at("uri"),input.value("require_authenticated",false));
        std::cout<<nlohmann::json{{"valid",true},{"verification",identity.verification},{"claims",identity.claims}}.dump()<<'\n';
    }catch(const gateway::sdk::VerificationUnavailable&){std::cerr<<"verification_unavailable\n";return 3;}
     catch(const gateway::sdk::UnsupportedVersion&){std::cerr<<"unsupported_version\n";return 4;}
     catch(const std::exception&){std::cerr<<"invalid_token_or_configuration\n";return 2;}
}
