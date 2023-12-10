import 'package:bitcoin_flutter/src/payments/index.dart' show PaymentData;
import 'package:bitcoin_flutter/src/payments/address/address.dart';
import 'package:bitcoin_flutter/src/payments/script/script.dart';
import 'package:test/test.dart';
import 'package:bitcoin_flutter/src/utils/script.dart' as bscript;
import 'package:bitcoin_flutter/src/utils/uint8list.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'dart:io';
import 'dart:convert';

main() {
  final fixtures =
      json.decode(new File("./test/fixtures/p2pkh.json").readAsStringSync(encoding: utf8));
  group('(valid case)', () {
    (fixtures["valid"] as List<dynamic>).forEach((f) {
      test(f['description'] + ' as expected', () {
        final arguments = _preformPaymentData(f['arguments']);
        final p2pkh = new P2pkhAddress(
          address: arguments.address,
          hash160: arguments.hash?.hex,
          pubkey: arguments.pubkey?.hex,
          signature: arguments.signature?.hex,
          scriptSig: arguments.input != null ? Script.fromRaw(byteData: arguments.input) : null,
          scriptPubKey:
              arguments.output != null ? Script.fromRaw(byteData: arguments.output) : null,
        );

        if (arguments.address == null) {
          expect(p2pkh.address, f['expected']['address']);
        }
        if (arguments.hash == null) {
          expect(p2pkh.h160, f['expected']['hash']);
        }
        if (arguments.pubkey == null) {
          expect(p2pkh.pubkey, f['expected']['pubkey']);
        }
        if (arguments.input == null && f['expected']['input'] != null) {
          expect(
              Script(script: [p2pkh.signature, p2pkh.pubkey]).toString(), f['expected']['input']);
        }
        if (arguments.output == null) {
          expect(p2pkh.scriptPubkey.toString(), f['expected']['output']);
        }
        if (arguments.signature == null) {
          expect(p2pkh.signature, f['expected']['signature']);
        }
      });
    });
  });
  group('(invalid case)', () {
    (fixtures["invalid"] as List<dynamic>).forEach((f) {
      test(
          'throws ' +
              f['exception'] +
              (f['description'] != null ? (' for ' + f['description']) : ''), () {
        final arguments = _preformPaymentData(f['arguments']);
        try {
          expect(
              new P2pkhAddress(
                address: arguments.address,
                hash160: arguments.hash?.hex,
                pubkey: arguments.pubkey?.hex,
                signature: arguments.signature?.hex,
                scriptSig:
                    arguments.input != null ? Script.fromRaw(byteData: arguments.input) : null,
                scriptPubKey:
                    arguments.output != null ? Script.fromRaw(byteData: arguments.output) : null,
              ),
              isArgumentError);
        } catch (err) {
          expect((err as ArgumentError).message, f['exception']);
        }
      });
    });
  });
}

PaymentData _preformPaymentData(dynamic x) {
  return new PaymentData(
      address: x['address'],
      hash: x['hash'] != null ? (x['hash'] as String).fromHex : null,
      input: x['input'] != null ? bscript.fromASM(x['input']) : null,
      output: x['output'] != null
          ? bscript.fromASM(x['output'])
          : x['outputHex'] != null
              ? (x['outputHex'] as String).fromHex
              : null,
      pubkey: x['pubkey'] != null ? (x['pubkey'] as String).fromHex : null,
      signature: x['signature'] != null ? (x['signature'] as String).fromHex : null);
}
