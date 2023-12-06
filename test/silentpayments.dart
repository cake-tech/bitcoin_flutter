import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:bitcoin_flutter/src/utils/bigint.dart';
import 'package:elliptic/elliptic.dart';
import 'package:bitcoin_flutter/src/payments/scanning.dart';
import 'package:bitcoin_flutter/src/payments/silentpayments.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:bitcoin_flutter/src/utils/uint8list.dart';
import 'package:bitcoin_flutter/src/utils/keys.dart';
import 'package:bitcoin_flutter/src/templates/silentpaymentaddress.dart';
import 'package:bitcoin_flutter/src/templates/outpoint.dart';
import 'package:bitcoin_flutter/src/ec/schnorr.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:test/test.dart';

main() {
  final curve = getSecp256k1();

  final fixtures =
      json.decode(new File('test/fixtures/silent_payments.json').readAsStringSync(encoding: utf8));

  for (var testCase in fixtures) {
    test(testCase['comment'], () {
      Map<String, List<(PublicKey, int)>> sendingOutputs = {};
      List<String> sendingOutputPubKeys = [];

      // Test sending
      for (var sendingTest in testCase['sending']) {
        var given = sendingTest["given"];

        List<PrivateKeyInfo> inputPrivKeys = [];
        for (List<dynamic> inputPrivKeyInfo in given['input_priv_keys']) {
          inputPrivKeys.add(
              PrivateKeyInfo(PrivateKey.fromHex(curve, inputPrivKeyInfo[0]), inputPrivKeyInfo[1]));
        }

        List<Outpoint> outpoints = [];
        for (List<dynamic> outpoint in given['outpoints']) {
          outpoints.add(Outpoint(txid: outpoint[0], index: outpoint[1]));
        }

        List<SilentPaymentDestination> silentPaymentDestinations = [];
        for (List<dynamic> recipientInfo in given['recipients']) {
          silentPaymentDestinations.add(
              SilentPaymentDestination.fromAddress(recipientInfo[0], recipientInfo[1].floor()));
        }

        sendingOutputs = SilentPayment.generateMultipleRecipientPubkeys(
            inputPrivKeys, SilentPayment.hashOutpoints(outpoints), silentPaymentDestinations);

        var expectedDestinations = sendingTest['expected']['outputs'];

        var i = 0;
        sendingOutputs.forEach((silentAddress, generatedOutputs) {
          final expectedSilentAddress = silentPaymentDestinations[i].toString();
          expect(silentAddress, expectedSilentAddress);

          generatedOutputs.forEach((output) {
            final expectedPubkey = expectedDestinations[i][0];
            final generatedPubkey = output.$1.toCompressedHex(); // TODO: program

            expect(generatedPubkey.fromHex.sublist(1).hex, expectedPubkey);

            sendingOutputPubKeys.add(generatedPubkey);

            final expectedAmount = expectedDestinations[i][1].floor();
            final returnedAmount = output.$2;
            expect(returnedAmount, expectedAmount);

            i++;
          });
        });
      }

      final msg = SHA256Digest().process(Uint8List.fromList(utf8.encode('message')));
      final aux = SHA256Digest().process(Uint8List.fromList(utf8.encode('random auxiliary data')));

      // Test receiving
      for (var receivingTest in testCase['receiving']) {
        var given = receivingTest["given"];

        List<dynamic> outputsToCheck = given['outputs'];

        // assert that the generated sending outputs are a subset
        // of the expected receiving outputs
        // i.e. all the generated outputs are present
        expect(
            sendingOutputPubKeys
                .every((element) => given['outputs'].contains(element.fromHex.sublist(1).hex)),
            true);

        var receivingAddresses = [];

        var silentPaymentReceiver = SilentPaymentReceiver.fromPrivKeys(
            scanPrivkey: PrivateKey.fromHex(curve, given["scan_priv_key"]),
            spendPrivkey: PrivateKey.fromHex(curve, given["spend_priv_key"]));

        // Add change address
        receivingAddresses.add(silentPaymentReceiver);

        Map<String, String>? labels = null;
        for (var label in given['labels'].entries) {
          final m = label.value;
          receivingAddresses.add(SilentPaymentAddress.createLabeledSilentPaymentAddress(
              silentPaymentReceiver.scanPubkey,
              silentPaymentReceiver.spendPubkey,
              Uint8List.fromList(HEX.decode(m))));

          if (labels == null) {
            labels = {};
          }
          labels[label.key] = m;
        }

        List<Outpoint> outpoints = [];
        for (var outpoint in given['outpoints']) {
          outpoints.add(Outpoint(txid: outpoint[0], index: outpoint[1]));
        }

        final outpointsHash = SilentPayment.hashOutpoints(outpoints);

        List<String> inputPubKeys = [];
        for (var inputPubKey in given['input_pub_keys']) {
          inputPubKeys.add(inputPubKey);
        }

        final addToWallet = scanOutputs(
            silentPaymentReceiver.scanPrivkey,
            silentPaymentReceiver.spendPubkey,
            getSumInputPubKeys(inputPubKeys),
            outpointsHash,
            outputsToCheck.map((e) => Uint8List.fromList(HEX.decode(e))).toList(),
            labels: labels);

        var expectedDestinations = receivingTest['expected']['outputs'];

        // Check that the private key is correct for the found output public key
        for (int i = 0; i < expectedDestinations.length; i++) {
          final output = addToWallet.entries.elementAt(i);
          final pubkey = output.key;
          final expectedPubkey = expectedDestinations[i]["pub_key"];
          expect(pubkey, expectedPubkey);

          final privKeyTweak = output.value;
          final expectedPrivKeyTweak = expectedDestinations[i]["priv_key_tweak"];
          expect(privKeyTweak, expectedPrivKeyTweak);

          final fullPrivateKey = PrivateKey(curve, silentPaymentReceiver.spendPrivkey.D)
              .tweakAdd(privKeyTweak.fromHex.bigint)!;

          if (fullPrivateKey.toCompressedHex().fromHex[0] == 0x03) {
            fullPrivateKey.negate();
          }

          // Sign the message with schnorr
          final sig = schnorrSign(msg, fullPrivateKey.D.decode, aux);

          // Verify the message is correct
          expect(verifySchnorr(msg, pubkey.fromHex, sig), true);

          // Verify the signature is correct
          expect(sig.hex, expectedDestinations[i]["signature"]);

          i++;
        }
      }
    });
  }
}
