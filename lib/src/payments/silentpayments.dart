import 'dart:typed_data';

import 'package:bitcoin_flutter/src/templates/outpoint.dart';
import 'package:bitcoin_flutter/src/utils/int.dart';
import 'package:bitcoin_flutter/src/utils/keys.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:crypto/crypto.dart';
import 'package:bitcoin_flutter/src/templates/silentpaymentaddress.dart';
import 'package:bitcoin_flutter/src/utils/uint8list.dart';
import 'package:elliptic/elliptic.dart';

class SilentPayment {
  SilentPayment();

  static List<Outpoint> decodeOutpoints(List<(String, int)> outpoints) =>
      outpoints.map((e) => Outpoint(txid: e.$1, index: e.$2)).toList();

  static Uint8List hashOutpoints(List<Outpoint> sendingData) {
    final outpoints = <Uint8List>[];

    for (final outpoint in sendingData) {
      final bytes = outpoint.txid.fromHex;
      final vout = outpoint.index;

      outpoints.add(concatenateUint8Lists(
          [Uint8List.fromList(bytes.reversed.toList()), vout.toBytesLittleEndian]));
    }

    outpoints.sort((a, b) => a.compare(b));

    final engine = sha256.convert(concatenateUint8Lists(outpoints));

    return Uint8List.fromList(engine.bytes);
  }

  static List<PrivateKeyInfo> decodePrivateKeys(List<(String, bool)> inputPrivKeys) => inputPrivKeys
      .map((input) => PrivateKeyInfo(PrivateKey.fromHex(getSecp256k1(), input.$1), input.$2))
      .toList();

  static PrivateKey getSumInputPrivKeys(List<PrivateKeyInfo> senderSecretKeys) {
    List<PrivateKey> negatedKeys = [];

    for (final info in senderSecretKeys) {
      final key = info.key;
      final isTaproot = info.isTaproot;

      if (isTaproot && key.toCompressedHex().fromHex[0] == 0x03) {
        negatedKeys.add(PrivateKey(getSecp256k1(), key.D).negate()!);
      } else {
        negatedKeys.add(key);
      }
    }

    final head = negatedKeys.first;
    final tail = negatedKeys.sublist(1);

    final result = tail.fold<PrivateKey>(
      head,
      (acc, item) =>
          PrivateKey(getSecp256k1(), acc.D).tweakAdd(item.toCompressedHex().fromHex.bigint)!,
    );

    return result;
  }

  static Map<String, List<(PublicKey, int)>> generateMultipleRecipientPubkeys(PrivateKey sum,
      Uint8List outpointHash, List<SilentPaymentDestination> silentPaymentDestinations) {
    // Group each destination by a different ecdhSharedSecret
    // { <scanPubKey>: (<ecdhSharedSecret>, [<silentPaymentDestination1>, <silentPaymentDestination2>...]) }
    Map<String, (PublicKey, List<SilentPaymentDestination>)> silentPaymentGroups = {};

    silentPaymentDestinations.forEach((silentPaymentDestination) {
      final scanPubKey = silentPaymentDestination.scanPubkey;
      final scanPubKeyStr = scanPubKey.toCompressedHex();

      if (silentPaymentGroups.containsKey(scanPubKeyStr)) {
        // Current key already in silentPaymentGroups, simply add up the new destination
        // with the already calculated ecdhSharedSecret
        final (ecdhSharedSecret, recipients) = silentPaymentGroups[scanPubKeyStr]!;
        silentPaymentGroups[scanPubKeyStr] =
            (ecdhSharedSecret, [...recipients, silentPaymentDestination]);
      } else {
        // New silent payment destination, calculate a new ecdhSharedSecret
        final ecdhSharedSecret = PublicKey.fromPoint(getSecp256k1(), scanPubKey)
            .tweakMul(outpointHash.bigint)!
            .tweakMul(sum.toCompressedHex().fromHex.bigint)!;
        silentPaymentGroups[scanPubKeyStr] = (ecdhSharedSecret, [silentPaymentDestination]);
      }
    });

    // Result destinations with amounts
    // { <silentPaymentAddress>: [(<tweakedPubKey1>, <amount>), (<tweakedPubKey2>, <amount>)...] }
    Map<String, List<(PublicKey, int)>> result = {};
    silentPaymentGroups.entries.forEach((group) {
      final (ecdhSharedSecret, destinations) = group.value;

      print(["ECDHSHAREDSECRET:", ecdhSharedSecret ]);

      int n = 0;
      destinations.forEach((destination) {
        final tweak =
            sha256.convert(ecdhSharedSecret.toCompressedHex().fromHex.concat([serialiseUint32(n)]));

        final res = PublicKey.fromPoint(getSecp256k1(), destination.spendPubkey)
            .tweakAdd(Uint8List.fromList(tweak.bytes).bigint);

      print(["RES:", res ]);

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
