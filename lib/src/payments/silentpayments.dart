import 'dart:typed_data';

import 'package:bitcoin_flutter/src/templates/outpoint.dart';
import 'package:bitcoin_flutter/src/utils/keys.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:crypto/crypto.dart';
import 'package:bitcoin_flutter/src/templates/silentpaymentaddress.dart';
import 'package:bitcoin_flutter/src/utils/int.dart';
import 'package:bitcoin_flutter/src/utils/uint8list.dart';
import 'package:coinlib/coinlib.dart';

class SilentPayment {
  SilentPayment();

  static List<Outpoint> decodeOutpoints(List<(String, int)> outpoints) =>
      outpoints.map((e) => Outpoint.fromHex(e.$1, e.$2)).toList();

  static Uint8List hashOutpoints(List<Outpoint> sendingData) {
    final outpoints = <Uint8List>[];

    for (final outpoint in sendingData) {
      final bytes = outpoint.hash;
      final vout = outpoint.n;

      outpoints.add(concatenateUint8Lists(
          [Uint8List.fromList(bytes.reversed.toList()), vout.toBytesLittleEndian]));
    }

    outpoints.sort((a, b) => a.compare(b));

    final engine = sha256.convert(concatenateUint8Lists(outpoints));

    return Uint8List.fromList(engine.bytes);
  }

  static List<PrivateKeyInfo> decodePrivateKeys(List<(String, bool)> inputPrivKeys) => inputPrivKeys
      .map((input) => PrivateKeyInfo(ECPrivateKey(input.$1.fromHex), input.$2))
      .toList();

  static ECPrivateKey getSumInputPrivKeys(List<PrivateKeyInfo> senderSecretKeys) {
    List<ECPrivateKey> negatedKeys = [];

    for (final info in senderSecretKeys) {
      final key = info.key;
      final isTaproot = info.isTaproot;

      if (isTaproot && key.compressed && key.data[0] == 0x03) {
        negatedKeys.add(key.negate()!);
      } else {
        negatedKeys.add(key);
      }
    }

    final head = negatedKeys.first;
    final tail = negatedKeys.sublist(1);

    final result = tail.fold<ECPrivateKey>(
      head,
      (acc, item) => acc.tweak(item.data)!,
    );

    return result;
  }

  static Map<String, List<(ECPublicKey, int)>> generateMultipleRecipientPubkeys(ECPrivateKey sum,
      Uint8List outpointHash, List<SilentPaymentDestination> silentPaymentDestinations) {
    // Group each destination by a different ecdhSharedSecret
    // { <scanPubKey>: (<ecdhSharedSecret>, [<silentPaymentDestination1>, <silentPaymentDestination2>...]) }
    Map<ECPublicKey, (ECPublicKey, List<SilentPaymentDestination>)> silentPaymentGroups = {};

    silentPaymentDestinations.forEach((silentPaymentDestination) {
      final scanPubKey = silentPaymentDestination.scanPubkey;

      if (silentPaymentGroups.containsKey(scanPubKey)) {
        // Current key already in silentPaymentGroups, simply add up the new destination
        // with the already calculated ecdhSharedSecret
        final (ecdhSharedSecret, recipients) = silentPaymentGroups[scanPubKey]!;
        silentPaymentGroups[scanPubKey] =
            (ecdhSharedSecret, [...recipients, silentPaymentDestination]);
      } else {
        // New silent payment destination, calculate a new ecdhSharedSecret
        final ecdhSharedSecret =
            scanPubKey.mul(outpointHash, compress: true)!.mul(sum.data, compress: true)!;
        silentPaymentGroups[scanPubKey] = (ecdhSharedSecret, [silentPaymentDestination]);
      }
    });

    // Result destinations with amounts
    // { <silentPaymentAddress>: [(<tweakedPubKey1>, <amount>), (<tweakedPubKey2>, <amount>)...] }
    Map<String, List<(ECPublicKey, int)>> result = {};
    silentPaymentGroups.entries.forEach((group) {
      final (ecdhSharedSecret, destinations) = group.value;

      int n = 0;
      destinations.forEach((destination) {
        final tweak = sha256Hash(ecdhSharedSecret.data.concat([serialiseUint32(n)]));

        final res = ECPublicKey(destination.spendPubkey.data).tweak(tweak)!;

        if (result.containsKey(destination.toString())) {
          result[destination.toString()]!.add((res, destination.amount));
        } else {
          result[destination.toString()] = [(res, destination.amount)];
        }

        n++;
      });
    });

    return result;
  }
}

Uint8List serialiseUint32(int n) {
  Uint8List buf = Uint8List(4);
  ByteData byteData = ByteData.view(buf.buffer);
  byteData.setUint32(0, n, Endian.big);
  return buf;
}
