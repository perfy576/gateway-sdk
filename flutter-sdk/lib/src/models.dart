const sdkVersion = '1.2.0';
const bindingCookieName = '__Host-gateway_binding';
const sessionCookieName = '__Host-gateway_session';

enum CheckResultCode { Ok, redictionToLogin }

class GatewayRequest {
  final String token;
  final String cookie;
  final String method;
  final String uri;

  const GatewayRequest(
      {required this.token,
      required this.cookie,
      required this.method,
      required this.uri});

  factory GatewayRequest.fromHeaders(Map<String, String> headers,
      {required String method, required String uri}) {
    final normalized = <String, String>{};
    for (final entry in headers.entries) {
      final name = entry.key.toLowerCase();
      if (normalized.containsKey(name) &&
          (name == 'cookie' || name == 'x-gateway-token')) {
        throw ArgumentError('Duplicate authentication header');
      }
      normalized[name] = entry.value;
    }
    return GatewayRequest(
        token: normalized['x-gateway-token'] ?? '',
        cookie: normalized['cookie'] ?? '',
        method: method,
        uri: uri);
  }
}

class Identity {
  final Map<String, dynamic> claims;
  final String verification;
  Identity(Map<String, dynamic> claims, this.verification)
      : claims = Map.unmodifiable(claims);
  bool get authenticated => claims['authenticated'] == true;
  String get userId => claims['sub'] as String;
  String get username => claims['username'] as String;
  String get displayName => claims['display_name'] as String;
  String get role => claims['role'] as String;
  int get tokenVersion => claims['ver'] as int;
}

class CheckResult {
  final CheckResultCode result;
  final String error;
  final String redictUrl;
  final int status;
  final Map<String, String> headers;
  final Identity? identity;
  CheckResult(
      {required this.result,
      this.error = '',
      this.redictUrl = '',
      this.status = 200,
      Map<String, String> headers = const {'Cache-Control': 'no-store'},
      this.identity})
      : headers = Map.unmodifiable(headers);
  bool get allowed => result == CheckResultCode.Ok;
}

class InvalidToken implements Exception {
  final String message;
  const InvalidToken(this.message);
  @override
  String toString() => message;
}

class UnsupportedVersion extends InvalidToken {
  const UnsupportedVersion(super.message);
}

class VerificationUnavailable implements Exception {
  final String message;
  const VerificationUnavailable(this.message);
  @override
  String toString() => message;
}

class GatewayClientException implements Exception {
  final String message;
  final int? status;
  const GatewayClientException(this.message, {this.status});
  @override
  String toString() => message;
}

class LoginRequest {
  final String appid;
  final String token;
  final Uri loginUrl;
  const LoginRequest(
      {required this.appid, required this.token, required this.loginUrl});
}

class LoginResult {
  final String result;
  final String retmsg;
  final String cookie;
  final int status;
  const LoginResult(
      {required this.result,
      required this.retmsg,
      required this.cookie,
      required this.status});
  bool get allowed => result == 'Ok';
}
