import 'dart:convert';
import 'dart:io';
import 'package:gateway_sdk/gateway_backend.dart';
import 'package:gateway_sdk/gateway_sdk.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

// Test-only routing to local Caddy; TLS still validates the real gateway name.
class LocalGatewayTransport extends http.BaseClient {
  final Uri gateway;
  late final IOClient _client;
  LocalGatewayTransport(this.gateway) {
    final io = HttpClient()
      ..findProxy = ((_) => 'DIRECT')
      ..connectionFactory = (_, __, ___) async {
        final task = await Socket.startConnect('127.0.0.1', 443);
        return ConnectionTask.fromSocket(
            task.socket.then(
                (socket) => SecureSocket.secure(socket, host: gateway.host)),
            task.cancel);
      };
    _client = IOClient(io);
  }
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final outbound = http.AbortableRequest(
        request.method,
        gateway.replace(
            path: request.url.path,
            query: request.url.hasQuery ? request.url.query : null),
        abortTrigger: request is http.Abortable ? request.abortTrigger : null)
      ..headers.addAll(request.headers)
      ..headers['Host'] = request.url.host
      ..bodyBytes = (request as http.Request).bodyBytes
      ..followRedirects = false;
    final response = await _client.send(outbound);
    if (response.statusCode >= 400) {
      stderr.writeln(
          'Test transport ${request.method} ${request.url.host}${request.url.path}: HTTP ${response.statusCode}');
    }
    return response;
  }

  @override
  void close() => _client.close();
}

void ensure(bool condition, String message) {
  if (!condition) throw StateError(message);
}

Future<void> main() async {
  final input = jsonDecode(await stdin.transform(utf8.decoder).join()) as Map;
  final origin = input['gateway_host'] as String;
  final host = input['audience'] as String;
  final appid = input['appid'] as String;
  final path = input['uri'] as String;
  final env = Platform.environment;
  final transport = LocalGatewayTransport(Uri.parse(origin));
  final app = GatewayClient(
      gatewayHost: origin,
      serviceHost: host,
      appid: appid,
      appPackage: 'com.example.gateway.integration',
      userAgent: 'GatewayFlutterIntegration/$sdkVersion',
      client: transport);
  final sdk =
      GatewaySDK(gatewayHost: origin, serviceHost: host, client: transport);
  final secret = env['GATEWAY_TOKEN_SECRET']!;
  try {
    final challenge = await app.beginLogin(path);
    final login = await app.login(
        username: env['GATEWAY_USERNAME']!,
        passwd: env['GATEWAY_PASSWORD']!,
        token: challenge.token);
    ensure(login.allowed && app.hasSession, 'Native challenge login failed');
    final session = app.exportSession()!;
    app.clearSession();
    ensure(!app.hasSession, 'Local session was not cleared');
    app.restoreSession(session);
    final response = await app.request('GET', path);
    ensure(response.statusCode == 200, 'Business request failed');
    final forwarded = jsonDecode(response.body) as Map<String, dynamic>;
    final headers = Map<String, String>.from(forwarded['headers'] as Map);
    ensure(!(headers['cookie'] ?? '').contains(sessionCookieName),
        'Session credential leaked upstream');
    final request =
        GatewayRequest.fromHeaders(headers, method: 'GET', uri: path);
    final local = await sdk.checkCookie(request, appid, secret);
    ensure(local.allowed && local.identity!.authenticated,
        'Dart local verification failed');
    final online = await sdk.verify(request, appid, secret,
        mode: VerificationMode.online, requireAuthenticated: true);
    ensure(online.verification == 'online', 'Dart HTTPS verification failed');
    final tampered = GatewayRequest(
        token: request.token,
        cookie: '$bindingCookieName=v1.${'0' * 64}',
        method: 'GET',
        uri: path);
    ensure(
        !(await sdk.checkCookie(tampered, appid, secret,
                allowOnlineFallback: true))
            .allowed,
        'Tampered binding was accepted');
    ensure(
        !(await sdk.checkCookie(
                GatewayRequest(
                    token: request.token,
                    cookie: request.cookie,
                    method: 'POST',
                    uri: path),
                appid,
                secret))
            .allowed,
        'Wrong request method was accepted');
    final signedToken = sdk.createLoginToken(appid, secret, uri: path);
    final apiLogin = await app.login(
        username: env['GATEWAY_USERNAME']!,
        passwd: env['GATEWAY_PASSWORD']!,
        token: signedToken);
    ensure(apiLogin.allowed, 'Dart-signed SDK login was rejected');
    final replay = await app.login(
        username: env['GATEWAY_USERNAME']!,
        passwd: env['GATEWAY_PASSWORD']!,
        token: signedToken);
    ensure(!replay.allowed && replay.status == 410,
        'Login token replay was accepted');
    final admin = await transport
        .get(Uri.parse('$origin/api/me'), headers: {'Cookie': apiLogin.cookie});
    ensure(admin.statusCode == 401, 'App session authorized admin');
    stdout.writeln(jsonEncode({
      'result': 'Ok',
      'username': local.identity!.username,
      'forwarded': {'token': request.token, 'cookie': request.cookie},
      'checks': [
        'native-challenge-login',
        'session-restore',
        'business-cookie-scope',
        'local-verification',
        'online-verification',
        'cookie-tamper',
        'method-binding',
        'dart-signed-login',
        'login-replay',
        'admin-isolation'
      ]
    }));
  } finally {
    app.close();
    sdk.close();
    transport.close();
  }
}
