import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:jose/jose.dart';
import 'package:test/test.dart';

final passwordTestKey = JsonWebKey.fromJson({
  ...jsonDecode(File('test/fixtures/password-key.json').readAsStringSync())
      as Map<String, dynamic>,
  'kid': 'a' * 64,
  'alg': 'RSA-OAEP-256',
});

Map<String, dynamic> passwordKeyResponse(String origin) => {
      'jwk': {
        'use': 'enc',
        for (final field in ['kty', 'n', 'e', 'kid', 'alg'])
          field: passwordTestKey.toJson()[field]
      },
      'audience': origin,
      'timestamp_ms': DateTime.now().millisecondsSinceEpoch,
    };

Future<Map<String, dynamic>> decryptPasswordEnvelope(String envelope) async {
  final parts = envelope.split('.');
  List<int> decode(String part) => base64Url.decode(base64Url.normalize(part));
  final header =
      jsonDecode(utf8.decode(decode(parts[0]))) as Map<String, dynamic>;
  expect(header, {
    'alg': 'RSA-OAEP-256',
    'enc': 'A256GCM',
    'kid': 'a' * 64,
    'typ': 'gateway-password+jwe'
  });
  final cek =
      passwordTestKey.unwrapKey(decode(parts[1]), algorithm: 'RSA-OAEP-256');
  final plaintext = cek.decrypt(decode(parts[3]),
      initializationVector: decode(parts[2]),
      authenticationTag: decode(parts[4]),
      additionalAuthenticatedData: parts[0].codeUnits,
      algorithm: 'A256GCM');
  final data = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
  expect(data['timestamp_ms'], isA<int>());
  return data;
}

/// Simulates the Gateway decrypting the wire payload before existing handlers.
class PasswordTestClient extends http.BaseClient {
  PasswordTestClient(this.inner);
  final http.Client inner;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (request.url.path == '/api/public/password-key') {
      return http.StreamedResponse(
          Stream.value(
              utf8.encode(jsonEncode(passwordKeyResponse(request.url.origin)))),
          200);
    }
    if (request.url.path != '/login' || request.method != 'POST') {
      return inner.send(request);
    }
    final body = jsonDecode(utf8.decode(await request.finalize().toBytes()))
        as Map<String, dynamic>;
    expect(body.containsKey('passwd'), isFalse);
    expect(body.containsKey('password'), isFalse);
    final payload = await decryptPasswordEnvelope(
        body.remove('password_envelope') as String);
    expect(payload['username'], body['username']);
    expect(payload['audience'], request.url.origin);
    expect(
        payload['context'], ['POST', '/login', body['appid'], body['token']]);
    final decoded = http.Request(request.method, request.url)
      ..followRedirects = request.followRedirects
      ..headers.addAll(request.headers)
      ..body = jsonEncode(
          {...body, 'passwd': (payload['passwords'] as Map)['password']});
    return inner.send(decoded);
  }

  @override
  void close() => inner.close();
}
