import 'dart:convert';
import 'package:gateway_sdk/gateway_sdk.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'password_fixture.dart';

const origin = 'https://gateway.example.com';
void main() {
  test('JWE uses authenticated algorithms and preserves long UTF-8 passwords',
      () async {
    final key = passwordKeyResponse(origin);
    final password = '密码"\\' * 28;
    String encrypt() => GatewayPasswordEnvelope.encrypt(
        keyResponse: key,
        audience: origin,
        username: 'alice',
        context: ['POST', '/api/login', 'admin', '', ''],
        passwords: {'password': password});
    final wire = encrypt();
    expect(wire, isNot(contains(password)));
    expect(wire, isNot(encrypt()));
    expect(
        jsonDecode(utf8.decode(
            base64Url.decode(base64Url.normalize(wire.split('.').first)))),
        {
          'alg': 'RSA-OAEP-256',
          'enc': 'A256GCM',
          'kid': 'a' * 64,
          'typ': 'gateway-password+jwe',
        });
    expect(await decryptPasswordEnvelope(wire), {
      'audience': origin,
      'username': 'alice',
      'timestamp_ms': key['timestamp_ms'],
      'context': ['POST', '/api/login', 'admin', '', ''],
      'passwords': {'password': password},
    });
  });
  test('untrusted keys and invalid metadata cannot encrypt credentials', () {
    final key = passwordKeyResponse(origin);
    final jwk = key['jwk'] as Map<String, dynamic>;
    for (final invalid in [
      {...key, 'audience': 'https://other.invalid'},
      {...key, 'timestamp_ms': 1.5},
      {
        ...key,
        'jwk': {...jwk, 'alg': 'RSA1_5'}
      },
      {
        ...key,
        'jwk': {...jwk, 'use': 'sig'}
      },
      {
        ...key,
        'jwk': {...jwk, 'n': 'AQAB'}
      },
      {
        ...key,
        'jwk': {...jwk, 'd': 'private-key-not-allowed'}
      },
    ]) {
      expect(
          () => GatewayPasswordEnvelope.encrypt(
              keyResponse: invalid,
              audience: origin,
              username: 'alice',
              context: ['POST', '/login'],
              passwords: {'password': 'secret'}),
          throwsA(isA<GatewayClientException>()));
    }
  });
  test('missing, redirected or malformed key responses never send a login POST',
      () async {
    for (final response in [
      http.Response('{}', 404),
      http.Response('', 302, headers: {'location': 'https://other.invalid'}),
      http.Response('<html>', 200),
      http.Response('{}', 200)
    ]) {
      final calls = <http.Request>[];
      final client = GatewayClient(
          gatewayHost: origin,
          serviceHost: 'app.example.com',
          appid: 'test',
          client: MockClient((r) async {
            calls.add(r);
            return response;
          }));
      addTearDown(client.close);
      await expectLater(
          client.login(username: 'alice', passwd: 'secret', token: 'challenge'),
          throwsA(isA<GatewayClientException>()));
      expect(calls, hasLength(1));
      expect(calls.single.method, 'GET');
      expect(calls.single.url.path, '/api/public/password-key');
      expect(calls.single.followRedirects, isFalse);
      expect(calls.single.body, isEmpty);
    }
  });
}
