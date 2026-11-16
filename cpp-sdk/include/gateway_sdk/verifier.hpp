#pragma once
#include <nlohmann/json.hpp>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>

namespace gateway::sdk {
inline constexpr const char *SDK_VERSION="1.2.0";
enum class Mode { Local, Auto, Online };
struct InvalidToken : std::runtime_error {using std::runtime_error::runtime_error;};
struct UnsupportedVersion : InvalidToken {using InvalidToken::InvalidToken;};
struct VerificationUnavailable : std::runtime_error {using std::runtime_error::runtime_error;};
struct Options {
    std::string secret,issuer,audience;
    Mode mode=Mode::Local;
    std::string verification_key,verify_url,ca_file;
    std::chrono::milliseconds timeout{3000};
};
struct Identity {
    bool authenticated;
    std::string user_id,username,display_name,role;
    int token_version;
    std::string verification;
    nlohmann::json claims;
};
// Immutable configuration; safe to reuse concurrently across request threads.
class Verifier {
    struct Impl;
    std::shared_ptr<const Impl> impl_;
public:
    explicit Verifier(Options options);
    Identity verify(const std::string& token,const std::string& cookie_header,const std::string& method,
                    const std::string& original_uri,bool require_authenticated=false) const;
};
}
