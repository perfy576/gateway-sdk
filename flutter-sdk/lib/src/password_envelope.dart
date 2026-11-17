import 'dart:convert';
import 'package:jose/jose.dart';

import 'models.dart';

/// JWE password transport. Fetch fresh key metadata for every submission.
class GatewayPasswordEnvelope {
  static String encrypt({
    required Map<String, dynamic> keyResponse,
    required String audience,
    required String username,
    required List<String> context,
    required Map<String, String> passwords,
  }) {
    try {
      final jwk = keyResponse['jwk'] as Map<String, dynamic>;
      final timestamp = keyResponse['timestamp_ms'];
      if (keyResponse['audience'] != audience ||
          timestamp is! int ||
          timestamp <= 0 ||
          timestamp > 9007199254740991 ||
          jwk['kty'] != 'RSA' ||
          jwk['alg'] != 'RSA-OAEP-256' ||
          jwk['use'] != 'enc' ||
          jwk['kid'] is! String ||
          !RegExp(r'^[a-f0-9]{64}$').hasMatch(jwk['kid'] as String) ||
          jwk.keys.any(
              (key) => !{'kty', 'n', 'e', 'kid', 'alg', 'use'}.contains(key))) {
        throw const FormatException('Invalid password encryption key');
      }
      final modulus = base64Url.decode(base64Url.normalize(jwk['n'] as String));
      if (modulus.length < 384 ||
          modulus.length > 1024 ||
          modulus.first == 0 ||
          (modulus.length == 384 && modulus.first < 128) ||
          jwk['e'] != 'AQAB') {
        throw const FormatException('Invalid RSA public key');
      }
      final builder = JsonWebEncryptionBuilder()
        ..encryptionAlgorithm = 'A256GCM'
        ..stringContent = jsonEncode({
          'audience': audience,
          'username': username,
          'context': context,
          'timestamp_ms': timestamp,
          'passwords': passwords,
        })
        ..setProtectedHeader('typ', 'gateway-password+jwe')
        // jose categorizes wrapping keys separately from JWK's standard enc use.
        ..addRecipient(JsonWebKey.fromJson(Map.of(jwk)..remove('use')),
            algorithm: 'RSA-OAEP-256');
      return builder.build().toCompactSerialization();
    } catch (_) {
      throw const GatewayClientException(
          'Invalid gateway password encryption key');
    }
  }
}
