import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:gateway_sdk/gateway_backend.dart';
import 'package:gateway_sdk/gateway_sdk.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'password_fixture.dart';

const origin = 'https://gateway.example.com';
const service = 'app.example.com';
const appid = 'Custom_App.2026';
final secret = 'ab' * 32;
final binding = 'v1.${'12' * 32}';
final cookie = '$bindingCookieName=$binding';
final session = '$sessionCookieName=v1.${'34' * 32}; $cookie';
const target = '/private?next=%2Fdocs&a=1';
String digest(String s) => sha256.convert(utf8.encode(s)).toString();
String derive(String context) =>
    Hmac(sha256, utf8.encode(secret)).convert(utf8.encode(context)).toString();

Map<String, dynamic> claims() {
  final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  return {
    'iss': origin,
    'aud': service,
    'appid': appid,
    'iat': now,
    'nbf': now - 2,
    'exp': now + 60,
    'ver': 1,
    'cookie_version': 1,
    'type': 'gateway_access',
    'authenticated': true,
    'sub': '42',
    'sid': '56' * 32,
    'username': 'alice',
    'display_name': 'Alice',
    'role': 'user',
    'request_method': 'GET',
    'request_uri_sha256': digest(target),
    'cookie_name': bindingCookieName,
    'cookie_sha256': digest(binding),
  };
}

String sign(Map<String, dynamic> data,
        {int version = 1, String? key, JWTAlgorithm? algorithm}) =>
    JWT(data, header: {'gwv': version}).sign(SecretKey(key ?? secret),
        algorithm: algorithm ?? JWTAlgorithm.HS256, noIssueAt: true);

GatewayRequest input(
        {String? token, String? cookies, String? method, String? uri}) =>
    GatewayRequest(
        token: token ?? sign(claims()),
        cookie: cookies ?? cookie,
        method: method ?? 'GET',
        uri: uri ?? target);

GatewaySDK backend({http.Client? client}) =>
    GatewaySDK(gatewayHost: origin, serviceHost: service, client: client);
GatewayClient native({http.Client? client}) => GatewayClient(
    gatewayHost: origin,
    serviceHost: service,
    appid: appid,
    client: client == null ? null : PasswordTestClient(client));

Map<String, dynamic> onlineResponse(GatewayRequest request,
        {Map<String, dynamic>? identity}) =>
    {
      'valid': true,
      'version': (identity ?? claims())['ver'],
      'claims': identity ?? claims(),
      'token_sha256': digest(request.token),
      'cookie_header_sha256': digest(request.cookie),
      'request_method': request.method,
      'request_uri_sha256': digest(request.uri),
    };

http.Response success() => http.Response(
    jsonEncode({
      'result': 'Ok',
      'retmsg': 'ok',
      'cookie': session,
    }),
    200);

void main() {
  group('trusted backend', () {
    test('valid gateway identity and two-result contract', () async {
      final sdk = backend();
      addTearDown(sdk.close);
      final result = await sdk.checkCookie(input(), appid, secret);
      expect(CheckResultCode.values.length, 2);
      expect(result.result, CheckResultCode.Ok);
      expect(result.error, isEmpty);
      expect(result.redictUrl, isEmpty);
      expect(result.identity!.username, 'alice');
      expect(result.identity!.verification, 'local');
    });

    test('login envelope uses isolated key, nonce, versions and return URL',
        () {
      final sdk = backend();
      addTearDown(sdk.close);
      final token = sdk.createLoginToken(appid, secret,
          uri: target, allowOnlineFallback: true);
      final jwt = JWT.verify(token, SecretKey(derive('gateway/sdk-login/v1')));
      final data = jwt.payload as Map;
      expect(jwt.header!['gwv'], 1);
      expect(jwt.header!['alg'], 'HS256');
      expect(data['appid'], appid);
      expect(data['return_url'], 'https://$service$target');
      expect(data['iss'], service);
      expect(data['aud'], '$origin/login');
      expect(data['exp'] - data['iat'], 300);
      expect(data['sdk_version'], sdkVersion);
      expect(data['token_versions'], [1]);
      expect(data['cookie_versions'], [1]);
      expect(data['allow_verify'], true);
      expect(data['jti'], matches(r'^[0-9a-f]{64}$'));
      expect(token, isNot(sdk.createLoginToken(appid, secret, uri: target)));
      expect(() => JWT.verify(token, SecretKey(secret)),
          throwsA(isA<JWTException>()));
    });

    final invalidClaims = <String, Map<String, dynamic>>{
      'appid': {'appid': 'other'},
      'issuer': {'iss': 'https://other.example.com'},
      'audience': {'aud': 'other.example.com'},
      'purpose': {'type': 'sdk_login'},
      'cookie digest': {'cookie_sha256': '0' * 64},
      'URI digest': {'request_uri_sha256': digest('/other')},
      'method': {'request_method': 'POST'},
      'timestamp type': {'iat': '1'},
      'expired': {'exp': 1},
      'long lifetime': {'exp': 9999999999},
      'identity': {'sid': 'bad'},
      'authenticated type': {'authenticated': 1},
      'missing username': {'username': null},
      'flag type': {'online_only': 'yes'},
      'cookie name': {'cookie_name': 'other'},
    };
    for (final entry in invalidClaims.entries) {
      test('reject ${entry.key} without online fallback', () async {
        var calls = 0;
        final sdk = backend(client: MockClient((_) async {
          calls++;
          return http.Response('{}', 200);
        }));
        addTearDown(sdk.close);
        final result = await sdk.checkCookie(
            input(token: sign({...claims(), ...entry.value})), appid, secret,
            redirectOnFailure: false, allowOnlineFallback: true);
        expect(result.result, CheckResultCode.redictionToLogin);
        expect(result.error, isNotEmpty);
        expect(result.headers['Location'], isNull);
        expect(result.redictUrl, startsWith('$origin/login?'));
        expect(calls, 0);
      });
    }

    test('signature tamper and alternate JWT algorithm never fallback',
        () async {
      var calls = 0;
      final sdk = backend(client: MockClient((_) async {
        calls++;
        return http.Response('{}', 200);
      }));
      addTearDown(sdk.close);
      for (final token in [
        sign(claims(), key: 'wrong'),
        sign(claims(), algorithm: JWTAlgorithm.HS384),
        'not.jwt'
      ]) {
        expect(
            (await sdk.checkCookie(input(token: token), appid, secret,
                    allowOnlineFallback: true))
                .allowed,
            false);
      }
      expect(calls, 0);
    });

    test(
        'missing and duplicate binding cookies reject, unrelated cookies accepted',
        () async {
      final sdk = backend();
      addTearDown(sdk.close);
      for (final cookies in [
        '',
        '$cookie; $cookie',
        '$bindingCookieName=v1.${'00' * 32}'
      ]) {
        final result =
            await sdk.checkCookie(input(cookies: cookies), appid, secret);
        expect(result.result, CheckResultCode.redictionToLogin);
        expect(result.status, 302);
        expect(result.headers['Location'], result.redictUrl);
        expect(result.error, startsWith('cookie_'));
      }
      expect(
          (await sdk.checkCookie(
                  input(cookies: 'app=ok; $cookie'), appid, secret))
              .allowed,
          true);
    });

    test('invalid original targets cannot become open redirects', () async {
      final sdk = backend();
      addTearDown(sdk.close);
      for (final uri in [
        '//evil.invalid',
        '/%2f/evil.invalid',
        '/x#fragment',
        '/%0d%0aHeader:bad',
        '/\\evil.invalid',
        '/_gateway/start'
      ]) {
        final result = await sdk.checkCookie(input(uri: uri), appid, secret);
        final login = Uri.parse(result.redictUrl);
        final token = JWT.verify(login.queryParameters['token']!,
            SecretKey(derive('gateway/sdk-login/v1')));
        expect(token.payload['return_url'], 'https://$service/');
      }
    });

    for (final kind in ['token version', 'cookie version', 'online_only']) {
      test('$kind requires explicit fallback and binds online response',
          () async {
        final data = {
          ...claims(),
          if (kind == 'token version') 'ver': 2,
          if (kind == 'cookie version') 'cookie_version': 2,
          if (kind == 'online_only') 'online_only': true
        };
        final request =
            input(token: sign(data, version: kind == 'token version' ? 2 : 1));
        var calls = 0;
        final sdk = backend(client: MockClient((r) async {
          calls++;
          expect(r.followRedirects, false);
          expect(r.url.toString(), '$origin/verify');
          expect(r.headers['Authorization'],
              'Bearer ${derive('gateway/verify-api/v1')}');
          expect(jsonDecode(r.body)['cookie'], request.cookie);
          return http.Response(
              jsonEncode(onlineResponse(request, identity: data)), 200);
        }));
        addTearDown(sdk.close);
        final denied = await sdk.checkCookie(request, appid, secret,
            redirectOnFailure: false);
        expect(denied.status, 426);
        expect(calls, 0);
        final accepted = await sdk.checkCookie(request, appid, secret,
            allowOnlineFallback: true);
        expect(accepted.allowed, true);
        expect(accepted.identity!.verification, 'online');
        expect(calls, 1);
      });
    }

    for (final field in [
      'token_sha256',
      'cookie_header_sha256',
      'request_method',
      'request_uri_sha256',
      'version',
      'claims'
    ]) {
      test('online mismatched $field fails closed', () async {
        final request = input();
        final sdk = backend(
            client: MockClient((_) async => http.Response(
                jsonEncode({...onlineResponse(request), field: 'bad'}), 200)));
        addTearDown(sdk.close);
        expect(
            sdk.verify(request, appid, secret, mode: VerificationMode.online),
            throwsA(isA<VerificationUnavailable>()));
      });
    }
    for (final status in [302, 401, 500]) {
      test('online HTTP $status fails closed', () async {
        final sdk = backend(
            client: MockClient((_) async => http.Response('{}', status,
                headers: {'location': 'https://other.invalid/'})));
        addTearDown(sdk.close);
        expect(
            sdk.verify(input(), appid, secret, mode: VerificationMode.online),
            throwsA(status == 401
                ? isA<InvalidToken>()
                : isA<VerificationUnavailable>()));
      });
    }
    test('online response size and timeout are bounded', () async {
      for (final slow in [false, true]) {
        final pending = Completer<http.Response>();
        final sdk = GatewaySDK(
            gatewayHost: origin,
            serviceHost: service,
            timeout: const Duration(milliseconds: 20),
            client: MockClient((_) => slow
                ? pending.future
                : Future.value(http.Response('x' * 65537, 200))));
        addTearDown(sdk.close);
        await expectLater(
            sdk.verify(input(), appid, secret, mode: VerificationMode.online),
            throwsA(isA<VerificationUnavailable>()));
        if (slow) pending.complete(http.Response('{}', 500));
      }
    });
    test('anonymous identity never passes high-level checkCookie', () async {
      final data = {
        ...claims(),
        'authenticated': false,
        for (final key in ['sub', 'sid', 'username', 'display_name', 'role'])
          key: ''
      };
      final sdk = backend();
      addTearDown(sdk.close);
      expect(
          (await sdk.verify(input(token: sign(data)), appid, secret))
              .authenticated,
          false);
      expect(
          (await sdk.checkCookie(input(token: sign(data)), appid, secret))
              .allowed,
          false);
    });
  });

  group('native Flutter client', () {
    test('secret-free challenge, JSON login and scoped business requests',
        () async {
      var step = 0;
      final client = GatewayClient(
          gatewayHost: origin,
          serviceHost: service,
          appid: appid,
          appPackage: 'com.example.reader',
          userAgent: 'Reader/2.0 (Flutter; android)',
          client: PasswordTestClient(MockClient((r) async {
            expect(r.followRedirects, false);
            expect(r.headers['X-Gateway-App-Package'], 'com.example.reader');
            expect(r.headers['User-Agent'], 'Reader/2.0 (Flutter; android)');
            switch (step++) {
              case 0:
                expect(r.url.toString(), 'https://$service$target');
                expect(r.headers['Cookie'], isNull);
                return http.Response('', 302, headers: {
                  'location': '$origin/login?appid=$appid&token=challenge'
                });
              case 1:
                expect(r.url.toString(), '$origin/login');
                expect(r.method, 'POST');
                expect(jsonDecode(r.body), {
                  'appid': appid,
                  'username': 'alice',
                  'passwd': 'password',
                  'token': 'challenge'
                });
                expect(r.headers['Cookie'], isNull);
                return success();
              default:
                expect(r.headers['Cookie'], session);
                expect(r.url.host, service);
                return http.Response('business', 200);
            }
          })));
      addTearDown(client.close);
      final challenge = await client.beginLogin(target);
      expect(challenge.appid, appid);
      expect(
          (await client.login(
                  username: 'alice',
                  passwd: 'password',
                  token: challenge.token))
              .allowed,
          true);
      expect(client.hasSession, true);
      expect((await client.request('GET', target)).body, 'business');
      expect(step, 3);
    });
    test(
        'legacy construction reports SDK agent without requiring an app package',
        () async {
      final client = native(client: MockClient((request) async {
        expect(request.headers['User-Agent'], 'GatewayFlutterSDK/$sdkVersion');
        expect(request.headers['X-Gateway-App-Package'], isNull);
        return http.Response('', 302, headers: {
          'location': '$origin/login?appid=$appid&token=challenge'
        });
      }));
      addTearDown(client.close);
      await client.beginLogin(target);
    });
    test('client metadata rejects header injection and oversized fields', () {
      for (final package in [
        'bad\r\nX-Evil: yes',
        'has space',
        'com.example\n',
        '.invalid',
        'a' * 256,
        '\u5305\u540d'
      ]) {
        expect(
            () => GatewayClient(
                gatewayHost: origin,
                serviceHost: service,
                appid: appid,
                appPackage: package),
            throwsArgumentError);
      }
      for (final agent in [
        '',
        'bad\r\nX-Evil: yes',
        'a' * 1025,
        '\u5ba2\u6237\u7aef'
      ]) {
        expect(
            () => GatewayClient(
                gatewayHost: origin,
                serviceHost: service,
                appid: appid,
                userAgent: agent),
            throwsArgumentError);
      }
    });
    test('invalid, foreign and ambiguous login URLs reject', () {
      final client = native();
      addTearDown(client.close);
      for (final url in [
        '/login',
        '%%%',
        'http://gateway.example.com/login',
        'https://evil.invalid/login?appid=$appid&token=x',
        '$origin/login?appid=other&token=x',
        '$origin/login?appid=$appid&token=x&token=y',
        '$origin/login?appid=$appid&appid=$appid&token=x',
        '$origin/login?appid=$appid&token=x#bad'
      ]) {
        expect(() => client.parseLoginUrl(url),
            throwsA(isA<GatewayClientException>()));
      }
    });
    test('failed or malformed login cannot install a cookie', () async {
      for (final response in [
        http.Response(
            jsonEncode({'result': 'Failed', 'retmsg': 'bad', 'cookie': ''}),
            401),
        http.Response(
            jsonEncode(
                {'result': 'Failed', 'retmsg': 'bad', 'cookie': session}),
            401),
        http.Response(
            jsonEncode({
              'result': 'Ok',
              'retmsg': 'ok',
              'cookie': '$session; other=x'
            }),
            200),
        http.Response(
            jsonEncode({'result': 'Ok', 'retmsg': 'ok', 'cookie': session}),
            302),
        http.Response('{}', 200)
      ]) {
        final client = native(client: MockClient((_) async => response));
        addTearDown(client.close);
        try {
          final result =
              await client.login(username: 'a', passwd: 'b', token: 't');
          expect(result.allowed, false);
          expect(result.cookie, isEmpty);
        } on GatewayClientException {/* malformed response is rejected */}
        expect(client.hasSession, false);
      }
    });
    test('local clear cancels in-flight login', () async {
      final response = Completer<http.Response>();
      final client = native(client: MockClient((_) => response.future));
      addTearDown(client.close);
      final future = client.login(username: 'a', passwd: 'b', token: 't');
      client.clearSession();
      response.complete(success());
      await expectLater(future, throwsA(isA<GatewayClientException>()));
      expect(client.hasSession, false);
    });
    test('session restore is gateway/service/app scoped and HTTP401 clears it',
        () async {
      final client =
          native(client: MockClient((_) async => http.Response('', 401)));
      addTearDown(client.close);
      final saved = {
        'gateway': origin,
        'serviceHost': service,
        'appid': appid,
        'cookie': session
      };
      client.restoreSession(saved);
      expect(client.exportSession(), saved);
      for (final key in ['gateway', 'serviceHost', 'appid']) {
        expect(() => client.restoreSession({...saved, key: 'other'}),
            throwsArgumentError);
      }
      await client.request('GET', target);
      expect(client.hasSession, false);
    });
    test('request cannot override destination or cookie', () async {
      final client = native();
      addTearDown(client.close);
      for (final uri in [
        'https://evil.invalid/',
        '//evil.invalid/',
        '/%2f/evil.invalid'
      ]) {
        await expectLater(client.request('GET', uri), throwsArgumentError);
      }
      for (final header in ['Cookie', 'cookie', 'Host', 'HOST']) {
        await expectLater(client.request('GET', '/', headers: {header: 'evil'}),
            throwsArgumentError);
      }
    });
    test('configuration validates HTTPS and credentials', () {
      for (final host in [
        'http://gateway.example.com',
        'https://u:p@gateway.example.com',
        '$origin/path',
        '$origin?query'
      ]) {
        expect(
            () => GatewayClient(
                gatewayHost: host, serviceHost: service, appid: appid),
            throwsArgumentError);
      }
      expect(() => native().restoreSession({'cookie': session}),
          throwsArgumentError);
      final sdk = backend();
      addTearDown(sdk.close);
      expect(
          () => sdk.createLoginToken('bad app', secret), throwsArgumentError);
      expect(() => sdk.createLoginToken(appid, 'bad'), throwsArgumentError);
    });
    test('header extraction rejects ambiguous auth headers', () {
      expect(
          GatewayRequest.fromHeaders({'COOKIE': cookie, 'X-Gateway-Token': 'x'},
                  method: 'GET', uri: '/')
              .cookie,
          cookie);
      expect(
          () => GatewayRequest.fromHeaders({'Cookie': cookie, 'cookie': cookie},
              method: 'GET', uri: '/'),
          throwsArgumentError);
    });
  });
}
