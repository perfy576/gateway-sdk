import 'dart:io';
import 'package:gateway_sdk/gateway_sdk.dart';

// Credentials come from the invoking environment, never from source control.
Future<void> main() async {
  final env = Platform.environment;
  final client = GatewayClient(
    gatewayHost: env['GATEWAY_HOST']!,
    serviceHost: env['GATEWAY_SERVICE_HOST']!,
    appid: env['GATEWAY_APPID']!,
    appPackage: env['GATEWAY_APP_PACKAGE'] ?? '',
  );
  try {
    final path = env['GATEWAY_REQUEST_PATH'] ?? '/private';
    final challenge = await client.beginLogin(path);
    final result = await client.login(
      username: env['GATEWAY_USERNAME']!,
      passwd: env['GATEWAY_PASSWORD']!,
      token: challenge.token,
    );
    if (!result.allowed) {
      stderr.writeln(result.retmsg);
      exitCode = 1;
      return;
    }
    final response = await client.request('GET', path);
    stdout.writeln('HTTP ${response.statusCode}');
  } finally {
    client.close();
  }
}
