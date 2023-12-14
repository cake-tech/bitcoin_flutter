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

  // https://github.com/bitcoin/bips/blob/c55f80c53c98642357712c1839cfdc0551d531c4/bip-0352.mediawiki#outpoints-hash
  // - The sender and receiver MUST calculate an outpoints hash for the transaction in the following manner:
  static Uint8List hashOutpoints(List<Outpoint> sendingData) {
    final outpoints = <Uint8List>[];

    // - Collect each outpoint used as an input to the transaction
    for (final outpoint in sendingData) {
      final bytes = outpoint.txid.fromHex;
      final vout = outpoint.index;

      outpoints.add(concatenateUint8Lists(
          [Uint8List.fromList(bytes.reversed.toList()), vout.toLittleEndianBytes]));
    }

    // - Let outpoints = outpoint_0 || ... || outpoint_n, sorted lexicographically by txid and vout, ascending order
    outpoints.sort((a, b) => a.compare(b));

    // - Let outpoints_hash = sha256(outpoints)
    return Uint8List.fromList(sha256.convert(concatenateUint8Lists(outpoints)).bytes);
  }

  // https://github.com/bitcoin/bips/blob/c55f80c53c98642357712c1839cfdc0551d531c4/bip-0352.mediawiki#creating-outputs
  static Map<String, List<(PublicKey, int)>> generateMultipleRecipientPubkeys(
      List<PrivateKeyInfo> inputPrivKeyInfos,
      Uint8List outpointsHash,
      List<SilentPaymentDestination> silentPaymentDestinations) {
    final curve = getSecp256k1();

    // - Let a_sum = a_0 + a_1 + ... + a_n, where each a_i has been negated if necessary
    PrivateKey? a_sum;
    PublicKey? A_sum;

    // - Collect the private keys for each input from the Inputs For Shared Secret Derivation list
    for (final info in inputPrivKeyInfos) {
      final key = info.key;
      final isTaproot = info.isTaproot;

      PrivateKey? negated;

      // - For each private key a_i corresponding to a BIP341 taproot output, check that the private key produces a point with an even y-value and negate the private key if not
      if (isTaproot && key.toCompressedHex().fromHex[0] == 0x03) {
        negated = PrivateKey(curve, key.D).negate()!;
      } else {
        negated = PrivateKey(curve, key.D);
      }

      if (a_sum == null) {
        a_sum = negated;
        A_sum = negated.publicKey;
      } else {
        a_sum = a_sum.tweakAdd(negated.D);
        A_sum!.pubkeyAdd(negated.publicKey);
      }
    }

    // Group each destination by a different ecdhSharedSecret
    // { <scanPubKey>: (<ecdhSharedSecret>, [<silentPaymentDestination1>, <silentPaymentDestination2>...]) }
    Map<String, (PublicKey, List<SilentPaymentDestination>)> silentPaymentGroups = {};

    silentPaymentDestinations.forEach((silentPaymentDestination) {
      final B_scan = silentPaymentDestination.scanPubkey;
      final scanPubKeyStr = B_scan.toCompressedHex();

      if (silentPaymentGroups.containsKey(scanPubKeyStr)) {
        // Current key already in silentPaymentGroups, simply add up the new destination
        // with the already calculated ecdhSharedSecret
        final (ecdhSharedSecret, recipients) = silentPaymentGroups[scanPubKeyStr]!;
        silentPaymentGroups[scanPubKeyStr] =
            (ecdhSharedSecret, [...recipients, silentPaymentDestination]);
      } else {
        // New silent payment destination, calculate a new ecdhSharedSecret
        final senderPartialSecret = PrivateKey(curve, a_sum!.D).tweakMul(outpointsHash.bigint)!.D;
        final ecdhSharedSecret = PublicKey.fromPoint(curve, B_scan).tweakMul(senderPartialSecret)!;

        silentPaymentGroups[scanPubKeyStr] = (ecdhSharedSecret, [silentPaymentDestination]);
      }
    });

    // Result destinations with amounts
    // { <silentPaymentAddress>: [(<tweakedPubKey1>, <amount>), (<tweakedPubKey2>, <amount>)...] }
    Map<String, List<(PublicKey, int)>> result = {};
    silentPaymentGroups.entries.forEach((group) {
      final (ecdhSharedSecret, destinations) = group.value;

      int k = 0;
      destinations.forEach((destination) {
        final t_k =
            sha256.convert(ecdhSharedSecret.toCompressedHex().fromHex.concat([k.toBigEndianBytes]));

        final P_mn = PublicKey.fromPoint(curve, destination.spendPubkey)
            .tweakAdd(Uint8List.fromList(t_k.bytes).bigint);

        if (result.containsKey(destination.toString())) {
          result[destination.toString()]!.add((P_mn, destination.amount));
        } else {
          result[destination.toString()] = [(P_mn, destination.amount)];
        }

        k++;
      });
    });

    return result;
  }
}
