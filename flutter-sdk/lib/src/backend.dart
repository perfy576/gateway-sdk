import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:http/http.dart' as http;
import 'common.dart';
import 'models.dart';

enum VerificationMode { local, auto, online }

String _digest(String input) => sha256.convert(utf8.encode(input)).toString();
String _derive(String secret, String context) =>
    Hmac(sha256, utf8.encode(secret)).convert(utf8.encode(context)).toString();
bool _equal(String a, String b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
  }
  return difference == 0;
}

int _version(dynamic value) {
  if (value is! int || value < 1) {
    throw const InvalidToken('Missing or invalid protocol version');
  }
  return value;
}

class _Credentials {
  final String appid, secret, loginKey, verificationKey;
  _Credentials(this.appid, this.secret, String? key)
      : loginKey = _derive(secret, 'gateway/sdk-login/v1'),
        verificationKey = key ?? _derive(secret, 'gateway/verify-api/v1');
}

/// Trusted servers only. Flutter applications should import gateway_sdk.dart.
class GatewaySDK {
  final Uri gateway;
  final String serviceHost;
  final Duration timeout;
  final String? verificationKey;
  final http.Client _client;
  final bool _ownsClient;
  final Random _random = Random.secure();
  _Credentials? _cached;

  GatewaySDK(
      {required String gatewayHost,
      required String serviceHost,
      this.timeout = const Duration(seconds: 3),
      this.verificationKey,
      http.Client? client})
      : gateway = httpsOrigin(gatewayHost),
        serviceHost = serviceHostname(serviceHost),
        _client = client ?? http.Client(),
        _ownsClient = client == null {
    if (timeout <= Duration.zero ||
        timeout > const Duration(seconds: 30) ||
        (verificationKey != null && !hex64Pattern.hasMatch(verificationKey!))) {
      throw ArgumentError('Invalid verification timeout or credentials');
    }
  }

  _Credentials _credentials(String appid, String secret) {
    validateAppid(appid);
    if (!hex64Pattern.hasMatch(secret)) {
      throw ArgumentError('Use the original 64-character service secret');
    }
    var cached = _cached;
    if (cached == null || cached.appid != appid || cached.secret != secret) {
      cached = _Credentials(appid, secret, verificationKey);
      _cached = cached;
    }
    return cached;
  }

  String createLoginToken(String appid, String secret,
      {String uri = '/', bool allowOnlineFallback = false}) {
    if (!validTarget('GET', uri)) {
      throw ArgumentError('Invalid login return target');
    }
    final credentials = _credentials(appid, secret);
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final nonce = List.generate(32, (_) => _random.nextInt(256))
        .map((v) => v.toRadixString(16).padLeft(2, '0'))
        .join();
    final claims = <String, dynamic>{
      'iss': serviceHost,
      'aud': '${gateway.origin}/login',
      'appid': appid,
      'iat': now,
      'nbf': now - 2,
      'exp': now + 300,
      'jti': nonce,
      'ver': 1,
      'type': 'sdk_login',
      'return_url': 'https://$serviceHost$uri',
      'sdk_version': sdkVersion,
      'token_versions': [1],
      'cookie_versions': [1],
      'allow_verify': allowOnlineFallback
    };
    return JWT(claims, header: {'gwv': 1}).sign(SecretKey(credentials.loginKey),
        algorithm: JWTAlgorithm.HS256, noIssueAt: true);
  }

  Future<CheckResult> checkCookie(
      GatewayRequest request, String appid, String secret,
      {bool redirectOnFailure = true, bool allowOnlineFallback = false}) async {
    _credentials(appid, secret);
    var uri = request.uri;
    var status = 401;
    String error;
    try {
      if (!validTarget(request.method, uri)) {
        uri = '/';
        status = 400;
        throw const InvalidToken('invalid_request: invalid return target');
      }
      if (!request.cookie
          .split(';')
          .any((v) => v.trimLeft().startsWith('$bindingCookieName='))) {
        throw const InvalidToken(
            'cookie_empty: gateway binding cookie is missing');
      }
      if (request.token.isEmpty) {
        throw const InvalidToken('token_empty: X-Gateway-Token is missing');
      }
      final identity = await verify(request, appid, secret,
          mode: allowOnlineFallback
              ? VerificationMode.auto
              : VerificationMode.local,
          requireAuthenticated: true);
      return CheckResult(result: CheckResultCode.Ok, identity: identity);
    } on VerificationUnavailable catch (e) {
      status = 503;
      error = 'verification_unavailable: ${e.message}';
    } on UnsupportedVersion catch (e) {
      status = 426;
      error = 'unsupported_version: ${e.message}';
    } on InvalidToken catch (e) {
      if (e.message.startsWith('cookie_empty:') ||
          e.message.startsWith('token_empty:') ||
          e.message.startsWith('invalid_request:')) {
        error = e.message;
      } else if (e.message.toLowerCase().contains('cookie') &&
          !e.message.toLowerCase().contains('token')) {
        error = 'cookie_invalid: ${e.message}';
      } else {
        error = 'token_invalid: ${e.message}';
      }
    }
    final token = createLoginToken(appid, secret,
        uri: uri, allowOnlineFallback: allowOnlineFallback);
    final url = gateway
        .resolve('/login')
        .replace(queryParameters: {'appid': appid, 'token': token}).toString();
    return CheckResult(
        result: CheckResultCode.redictionToLogin,
        error: error,
        redictUrl: url,
        status: redirectOnFailure ? 302 : status,
        headers: {
          'Cache-Control': 'no-store',
          if (redirectOnFailure) 'Location': url
        });
  }

  Future<Identity> verify(GatewayRequest request, String appid, String secret,
      {VerificationMode mode = VerificationMode.local,
      bool requireAuthenticated = false}) async {
    final credentials = _credentials(appid, secret);
    if (request.token.isEmpty ||
        utf8.encode(request.token).length > 16384 ||
        utf8.encode(request.cookie).length > 32768 ||
        !validTarget(request.method, request.uri) ||
        request.cookie.runes.any((c) => c < 32 || c == 127)) {
      throw const InvalidToken('Invalid verification input');
    }
    late Map<String, dynamic> claims;
    var source = 'local';
    if (mode == VerificationMode.online) {
      claims = await _online(request, credentials);
      source = 'online';
    } else {
      try {
        claims = _local(request, credentials);
      } on UnsupportedVersion {
        if (mode != VerificationMode.auto) rethrow;
        claims = await _online(request, credentials);
        source = 'online';
      }
    }
    if (claims['appid'] != appid ||
        claims['authenticated'] is! bool ||
        ['sub', 'sid', 'username', 'display_name', 'role']
            .any((key) => claims[key] is! String)) {
      throw const InvalidToken('Invalid token appid or identity');
    }
    final authenticated = claims['authenticated'] as bool;
    if (authenticated
        ? ((claims['sub'] as String).isEmpty ||
            !hex64Pattern.hasMatch(claims['sid'] as String))
        : ['sub', 'sid', 'username', 'display_name', 'role']
            .any((key) => claims[key] != '')) {
      throw const InvalidToken('Invalid session identity');
    }
    if (requireAuthenticated && !authenticated) {
      throw const InvalidToken('Authenticated identity required');
    }
    _version(claims['ver']);
    return Identity(claims, source);
  }

  Map<String, dynamic> _local(
      GatewayRequest request, _Credentials credentials) {
    try {
      final decoded = JWT.decode(request.token);
      final header = decoded.header;
      if (header == null) throw const InvalidToken('Missing token header');
      if (_version(header['gwv']) != 1) {
        throw const UnsupportedVersion('Unsupported gateway token version');
      }
      // Pin the algorithm before invoking the library's algorithm-dispatching verifier.
      if (header['alg'] != 'HS256' || header['typ'] != 'JWT') {
        throw const InvalidToken('Unsupported JWT algorithm or type');
      }
      final claims = jsonObject(jsonEncode(decoded.payload));
      for (final key in [
        'iss',
        'aud',
        'sub',
        'sid',
        'username',
        'display_name',
        'role',
        'type',
        'cookie_name',
        'cookie_sha256',
        'request_method',
        'request_uri_sha256'
      ]) {
        if (claims[key] is! String) {
          throw const InvalidToken('Missing string claim');
        }
      }
      if (claims['iss'] != gateway.origin ||
          claims['aud'] != serviceHost ||
          _version(claims['ver']) != 1) {
        throw const InvalidToken('Token scope or version mismatch');
      }
      if (['iat', 'nbf', 'exp'].any((key) => claims[key] is! int)) {
        throw const InvalidToken('Missing integer timestamp');
      }
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final iat = claims['iat'] as int,
          nbf = claims['nbf'] as int,
          exp = claims['exp'] as int;
      if (iat < now - 63 ||
          iat > now + 3 ||
          nbf < now - 66 ||
          nbf > now + 3 ||
          exp <= now - 3 ||
          exp > now + 63 ||
          exp <= iat ||
          exp - iat > 60) {
        throw const InvalidToken('Invalid token lifetime');
      }
      JWT.verify(request.token, SecretKey(credentials.secret),
          checkExpiresIn: false, checkNotBefore: false);
      if (_version(claims['cookie_version']) != 1) {
        throw const UnsupportedVersion('Unsupported gateway cookie version');
      }
      if (claims['type'] != 'gateway_access' ||
          claims['cookie_name'] != bindingCookieName) {
        throw const InvalidToken('Wrong token purpose');
      }
      if (claims.containsKey('online_only') && claims['online_only'] is! bool) {
        throw const InvalidToken('Invalid protocol negotiation flag');
      }
      if (claims['online_only'] == true) {
        throw const UnsupportedVersion(
            'Negotiated protocol requires online verification');
      }
      if (claims['request_method'] != request.method ||
          !_equal(
              claims['request_uri_sha256'] as String, _digest(request.uri))) {
        throw const InvalidToken('Token does not match this request');
      }
      final cookies = request.cookie
          .split(';')
          .map((v) => v.trimLeft())
          .where((v) => v.startsWith('$bindingCookieName='))
          .toList();
      if (cookies.length != 1) {
        throw const InvalidToken('Missing or duplicate gateway binding cookie');
      }
      final binding = cookies.single.substring(bindingCookieName.length + 1);
      if (!binding.startsWith('v1.') ||
          !hex64Pattern.hasMatch(binding.substring(3)) ||
          !_equal(claims['cookie_sha256'] as String, _digest(binding))) {
        throw const InvalidToken('Gateway cookie mismatch');
      }
      return claims;
    } on InvalidToken {
      rethrow;
    } catch (_) {
      throw const InvalidToken('Invalid gateway token');
    }
  }

  Future<Map<String, dynamic>> _online(
      GatewayRequest input, _Credentials credentials) async {
    final request = http.Request('POST', gateway.resolve('/verify'))
      ..headers.addAll({
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ${credentials.verificationKey}'
      })
      ..body = jsonEncode({
        'audience': serviceHost,
        'token': input.token,
        'cookie': input.cookie,
        'method': input.method,
        'uri': input.uri
      });
    http.Response response;
    try {
      response = await limitedResponse(_client, request, timeout);
    } catch (_) {
      throw const VerificationUnavailable(
          'Gateway HTTPS verification is unavailable');
    }
    if ([400, 401, 403, 404, 422].contains(response.statusCode)) {
      throw const InvalidToken('Gateway rejected token, cookie or credentials');
    }
    if (response.statusCode != 200) {
      throw const VerificationUnavailable(
          'Unexpected gateway verification HTTP status');
    }
    try {
      final value = jsonObject(response.body);
      final claims = value['claims'];
      if (value['valid'] != true || claims is! Map<String, dynamic>) {
        throw const FormatException();
      }
      final expected = {
        'token_sha256': _digest(input.token),
        'cookie_header_sha256': _digest(input.cookie),
        'request_method': input.method,
        'request_uri_sha256': _digest(input.uri)
      };
      for (final entry in expected.entries) {
        if (value[entry.key] is! String ||
            !_equal(value[entry.key] as String, entry.value)) {
          throw const FormatException();
        }
      }
      if (claims['iss'] != gateway.origin ||
          claims['aud'] != serviceHost ||
          _version(value['version']) != _version(claims['ver'])) {
        throw const FormatException();
      }
      return claims;
    } catch (_) {
      throw const VerificationUnavailable(
          'Malformed or mismatched verification response');
    }
  }

  void close() {
    if (_ownsClient) _client.close();
  }
}
