import 'dart:convert';
import 'dart:io';
import 'package:gateway_sdk/gateway_sdk.dart';

Future<void> main() async {
  final input = jsonDecode(await stdin.transform(utf8.decoder).join())
      as Map<String, dynamic>;
  stdout.write(GatewayPasswordEnvelope.encrypt(
    keyResponse: Map<String, dynamic>.from(input['key_response'] as Map),
    audience: input['audience'] as String,
    username: input['username'] as String,
    context: List<String>.from(input['context'] as List),
    passwords: Map<String, String>.from(input['passwords'] as Map),
  ));
}
