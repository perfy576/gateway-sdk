import 'dart:convert';
import 'package:http/http.dart' as http;
import 'common.dart';
import 'models.dart';

/// Native Flutter/Dart client. The application owns any persistent secure storage.
class GatewayClient {
  final Uri gateway;
  final String serviceHost;
  final String appid;
  final String appPackage;
  final String userAgent;
  final Duration timeout;
  final http.Client _client;
  final bool _ownsClient;
  String _cookie = '';
  int _loginGeneration = 0;
  static const _web = bool.fromEnvironment('dart.library.js_interop') ||
      bool.fromEnvironment('dart.library.html');

  GatewayClient(
      {required String gatewayHost,
      required String serviceHost,
      required this.appid,
      this.appPackage = '',
      this.userAgent = 'GatewayFlutterSDK/$sdkVersion',
      this.timeout = const Duration(seconds: 10),
      http.Client? client})
      : gateway = httpsOrigin(gatewayHost),
        serviceHost = serviceHostname(serviceHost),
        _client = client ?? http.Client(),
        _ownsClient = client == null {
    validateAppid(appid);
    if (appPackage.isNotEmpty &&
        RegExp(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$').stringMatch(appPackage) !=
            appPackage) {
      throw ArgumentError('Invalid application package name');
    }
    if (userAgent.isEmpty ||
        userAgent.length > 1024 ||
        userAgent.codeUnits.any((c) => c < 32 || c > 126)) {
      throw ArgumentError(
          'User-Agent must contain 1..1024 printable ASCII characters');
    }
    if (timeout <= Duration.zero || timeout > const Duration(seconds: 30)) {
      throw ArgumentError('Timeout must be within 0..30 seconds');
    }
  }

  void _native() {
    if (_web) {
      throw UnsupportedError(
          'Browser Cookie/HttpOnly restrictions require browser SSO; the JSON cookie client is native-only.');
    }
  }

  /// A stored cookie is not proof of a currently valid server-side session.
  bool get hasSession => _cookie.isNotEmpty;

  Map<String, String> get _clientHeaders => {
        'User-Agent': userAgent,
        if (appPackage.isNotEmpty) 'X-Gateway-App-Package': appPackage,
      };

  /// Obtain the existing gateway-issued challenge without shipping an app secret.
  Future<LoginRequest> beginLogin(String uri) async {
    _native();
    final request = http.Request('GET', serviceUri(serviceHost, 'GET', uri))
      ..headers.addAll(_clientHeaders);
    final response = await limitedResponse(_client, request, timeout);
    if (response.statusCode != 302 && response.statusCode != 303) {
      throw GatewayClientException(
          'The target did not return a gateway login challenge; choose a protected path.',
          status: response.statusCode);
    }
    return parseLoginUrl(response.headers['location'] ?? '');
  }

  LoginRequest parseLoginUrl(String location) {
    final Uri url;
    try {
      url = Uri.parse(location);
    } on FormatException {
      throw const GatewayClientException('Malformed gateway login URL');
    }
    if (url.scheme != 'https' ||
        url.host.isEmpty ||
        url.origin != gateway.origin ||
        url.path != '/login' ||
        url.hasFragment ||
        url.userInfo.isNotEmpty ||
        url.queryParametersAll['appid']?.length != 1 ||
        url.queryParametersAll['token']?.length != 1 ||
        url.queryParameters['appid'] != appid) {
      throw const GatewayClientException(
          'Login URL is not bound to this gateway and appid');
    }
    final token = url.queryParameters['token']!;
    if (token.isEmpty || utf8.encode(token).length > 16384) {
      throw const GatewayClientException('Missing or oversized login token');
    }
    return LoginRequest(appid: appid, token: token, loginUrl: url);
  }

  Future<LoginResult> login(
      {required String username,
      required String passwd,
      required String token}) async {
    _native();
    if (username.isEmpty ||
        utf8.encode(username).length > 64 ||
        passwd.isEmpty ||
        utf8.encode(passwd).length > 256 ||
        token.isEmpty ||
        utf8.encode(token).length > 16384) {
      throw ArgumentError('Invalid login credentials or token');
    }
    final generation = ++_loginGeneration;
    final request = http.Request('POST', gateway.resolve('/login'))
      ..headers.addAll(_clientHeaders)
      ..headers['Content-Type'] = 'application/json'
      ..body = jsonEncode({
        'appid': appid,
        'username': username,
        'passwd': passwd,
        'token': token
      });
    final response = await limitedResponse(_client, request, timeout);
    Map<String, dynamic> value;
    try {
      value = jsonObject(response.body);
      if (value['retmsg'] is! String ||
          value['cookie'] is! String ||
          (value['result'] != 'Ok' && value['result'] != 'Failed')) {
        throw const FormatException();
      }
      if (value['result'] == 'Ok') {
        if (response.statusCode != 200) throw const FormatException();
        final cookie = sessionCookie(value['cookie'] as String);
        if (generation != _loginGeneration) {
          throw const GatewayClientException(
              'Login result was superseded or cancelled');
        }
        _cookie = cookie;
      } else if (response.statusCode >= 200 && response.statusCode < 300 ||
          value['cookie'] != '') {
        throw const FormatException();
      }
    } on FormatException {
      throw GatewayClientException('Malformed gateway login response',
          status: response.statusCode);
    }
    return LoginResult(
        result: value['result'] as String,
        retmsg: value['retmsg'] as String,
        cookie: value['result'] == 'Ok' ? _cookie : '',
        status: response.statusCode);
  }

  /// Cookies are attached only to this configured service. Redirects never follow.
  Future<http.Response> request(String method, String uri,
      {Map<String, String> headers = const {}, Object? body}) async {
    _native();
    if (headers.keys.any((key) =>
        key.toLowerCase() == 'cookie' || key.toLowerCase() == 'host')) {
      throw ArgumentError(
          'Cookie and Host headers are managed by GatewayClient');
    }
    final request = http.Request(method, serviceUri(serviceHost, method, uri))
      ..followRedirects = false
      ..headers.addAll(_clientHeaders)
      ..headers.addAll(headers);
    final cookie = _cookie;
    if (cookie.isNotEmpty) request.headers['Cookie'] = cookie;
    if (body is String) {
      request.body = body;
    } else if (body is List<int>) {
      request.bodyBytes = body;
    } else if (body != null) {
      throw ArgumentError('Request body must be a string or bytes');
    }
    final response = await limitedResponse(_client, request, timeout,
        limit: 16 * 1024 * 1024);
    if (response.statusCode == 401 && _cookie == cookie) clearSession();
    return response;
  }

  /// Persist only with application-provided secure storage; never save passwords.
  Map<String, String>? exportSession() => hasSession
      ? {
          'gateway': gateway.origin,
          'serviceHost': serviceHost,
          'appid': appid,
          'cookie': _cookie
        }
      : null;

  void restoreSession(Map<String, String> session) {
    _native();
    if (session['gateway'] != gateway.origin ||
        session['serviceHost'] != serviceHost ||
        session['appid'] != appid) {
      throw ArgumentError(
          'Session belongs to a different gateway, service, or appid');
    }
    _loginGeneration++;
    _cookie = sessionCookie(session['cookie'] ?? '');
  }

  /// Local logout; it does not revoke the server's in-memory session.
  void clearSession() {
    _loginGeneration++;
    _cookie = '';
  }

  void close() {
    clearSession();
    if (_ownsClient) _client.close();
  }
}
