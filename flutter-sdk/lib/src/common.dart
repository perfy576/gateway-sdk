import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'models.dart';

final appidPattern = RegExp(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$');
final hex64Pattern = RegExp(r'^[0-9a-f]{64}$');

Uri httpsOrigin(String input) {
  if (input.runes.any((c) => c <= 32 || c == 127)) {
    throw ArgumentError('Invalid HTTPS origin');
  }
  final uri = Uri.parse(input.contains('://') ? input : 'https://$input');
  if (uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      (uri.path.isNotEmpty && uri.path != '/') ||
      uri.hasQuery ||
      uri.hasFragment ||
      uri.port < 1 ||
      uri.port > 65535) {
    throw ArgumentError(
        'Configure an HTTPS origin without credentials or a path');
  }
  return Uri(
      scheme: 'https',
      host: uri.host.toLowerCase(),
      port: uri.hasPort && uri.port != 443 ? uri.port : null);
}

String serviceHostname(String value) {
  if (value.length > 253 ||
      !RegExp(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$')
          .hasMatch(value)) {
    throw ArgumentError('Configure the registered business hostname');
  }
  return value;
}

bool validTarget(String method, String uri) {
  if (!RegExp(r'^[A-Z]{1,32}$').hasMatch(method) ||
      !uri.startsWith('/') ||
      uri.startsWith('//') ||
      uri.startsWith('/_gateway/') ||
      utf8.encode(uri).length > 4096 ||
      uri.contains('#')) {
    return false;
  }
  try {
    final decoded = Uri.decodeComponent(uri);
    return !decoded.startsWith('//') &&
        !(uri + decoded).runes.any((c) => c < 32 || c == 127 || c == 92);
  } on FormatException {
    return false;
  }
}

Uri serviceUri(String host, String method, String target) {
  if (!validTarget(method, target)) {
    throw ArgumentError('Invalid original request target');
  }
  return Uri.parse('https://$host$target');
}

void validateAppid(String appid) {
  if (!appidPattern.hasMatch(appid)) throw ArgumentError('Invalid appid');
}

Future<http.Response> limitedResponse(
    http.Client client, http.Request request, Duration timeout,
    {int limit = 65536}) async {
  // Bound both headers and body within the same timeout, with redirects disabled.
  final abort = Completer<void>();
  final outbound = http.AbortableRequest(request.method, request.url,
      abortTrigger: abort.future)
    ..headers.addAll(request.headers)
    ..bodyBytes = request.bodyBytes
    ..followRedirects = false;
  try {
    return await (() async {
      final response = await client.send(outbound);
      final chunks = <int>[];
      await for (final chunk in response.stream) {
        if (chunks.length + chunk.length > limit) {
          throw const GatewayClientException('Gateway response is too large');
        }
        chunks.addAll(chunk);
      }
      return http.Response.bytes(chunks, response.statusCode,
          headers: response.headers);
    })()
        .timeout(timeout);
  } finally {
    abort.complete();
  }
}

Map<String, dynamic> jsonObject(String input) {
  final value = jsonDecode(input);
  if (value is! Map<String, dynamic>) {
    throw const FormatException('Expected a JSON object');
  }
  return value;
}

String sessionCookie(String input) {
  final values = <String, String>{};
  if (input.length > 8192 || input.runes.any((c) => c < 32 || c == 127)) {
    throw const FormatException('Invalid session cookie');
  }
  for (final part in input.split(';')) {
    final index = part.indexOf('=');
    if (index < 1) throw const FormatException('Invalid session cookie');
    final key = part.substring(0, index).trim();
    final value = part.substring(index + 1);
    if ((key != sessionCookieName && key != bindingCookieName) ||
        values.containsKey(key) ||
        !RegExp(r'^v[1-9][0-9]*\.[A-Za-z0-9._~-]+$').hasMatch(value) ||
        (value.startsWith('v1.') &&
            !hex64Pattern.hasMatch(value.substring(3)))) {
      throw const FormatException('Invalid session cookie');
    }
    values[key] = value;
  }
  if (values.length != 2) {
    throw const FormatException('Both gateway cookies are required');
  }
  return '$sessionCookieName=${values[sessionCookieName]}; $bindingCookieName=${values[bindingCookieName]}';
}
