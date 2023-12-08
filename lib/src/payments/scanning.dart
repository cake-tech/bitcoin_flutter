import 'dart:typed_data';
import 'package:bitcoin_flutter/src/utils/int.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:elliptic/elliptic.dart';
import 'package:crypto/crypto.dart';
import '../utils/uint8list.dart';

// https://github.com/bitcoin/bips/blob/c55f80c53c98642357712c1839cfdc0551d531c4/bip-0352.mediawiki#scanning
// https://github.com/bitcoin-core-review-club/bips/blob/cfe0771a0408a2d2de278d4e95bb9a33bd1615b2/bip-0352/reference.py#L105

// RETURNS: [{output: [tweak, label]}]
// Maps the output pubkey to the tweak used for the shared secret, and the label used to derive the tweak if applicable
Map<String, List<String>> scanOutputs(PrivateKey b_scan, PublicKey B_spend, PublicKey A_sum,
    Uint8List outpointsHash, List<Uint8List> outputPubKeys,
    {Map<String, String>? labels}) {
  final curve = getSecp256k1();

  // - Let ecdh_shared_secret = outpoints_hash·b_scan·A
  final tweakDataForRecipient = PublicKey.fromPoint(curve, A_sum).tweakMul(outpointsHash.bigint);
  final ecdhSharedSecret = tweakDataForRecipient!.tweakMul(b_scan.D);

  // P_k to priv key tweak matches
  final matches = <String, List<String>>{};

  // - Starting with k = 0:
  var k = 0;

  do {
    // - Let t_k = sha256(serP(ecdh_shared_secret) || ser32(k))
    final t_k = sha256
        .convert(ecdhSharedSecret!.toCompressedHex().fromHex.concat([k.toBigEndianBytes]))
        .toString()
        .fromHex;

    // - Compute P_k = B_spend + t_k·G
    final P_k = PublicKey.fromPoint(curve, B_spend).tweakAdd(t_k.bigint).toCompressedHex().fromHex;
    final length = outputPubKeys.length;

    // - For each output in outputPubKeys
    for (var i = 0; i < length; i++) {
      final output = outputPubKeys[i];

      // - If P_k equals output
      if (output.sublist(1) != P_k.sublist(1)
          ? output.hex == P_k.sublist(1).hex
          : output.sublist(1).hex == P_k.sublist(1).hex) {
        // - Add P_k to the wallet
        matches[output.hex] = [t_k.hex];
        outputPubKeys.removeAt(i);
        k++; // Increment counter
        break;
      }

      // - Else, if the wallet has precomputed labels (including the change label, if used)
      if (labels != null && labels.isNotEmpty) {
        final outputPubkey = PublicKey.fromBytes(curve, output);

        // - Compute m·G = output - Pk
        // m·G = output + (-P_k)
        final negatedP_k = PublicKey.fromBytes(curve, P_k).negate();
        var m_G_sub = PublicKey.fromPoint(curve, outputPubkey)
            .pubkeyAdd(negatedP_k)
            .toCompressedHex()
            .fromHex;

        // - Check if m·G exists in the list of labels used by the wallet
        var m_G = labels[m_G_sub.hex];

        // - If the label is not found, negate output and check again
        if (m_G == null) {
          outputPubkey.negate();
          m_G_sub = PublicKey.fromPoint(curve, outputPubkey)
              .pubkeyAdd(negatedP_k)
              .toCompressedHex()
              .fromHex;

          m_G = labels[m_G_sub.hex];
        }

        // - If a match is found:
        if (m_G != null) {
          //  - Add the P_k + m·G to the wallet
          final P_km = PublicKey.fromBytes(curve, P_k)
              .tweakAdd(m_G.fromHex.bigint)
              .toCompressedHex()
              .fromHex;

          if (P_km[0] == 0x03) {
            P_km[0] = 0x02;
          }

          matches[output.hex] = [
            PrivateKey.fromBytes(curve, t_k).tweakAdd(m_G.fromHex.bigint)!.toCompressedHex(),
            m_G
          ];

          outputPubKeys.removeAt(i);
          k++; // Increment counter
          break;
        } else {
          final found = labels.values.any((tweak) {
            final B_m = PublicKey.fromPoint(curve, B_spend).tweakAdd(tweak.fromHex.bigint);
            final P_km =
                PublicKey.fromPoint(curve, B_m).tweakAdd(t_k.bigint).toCompressedHex().fromHex;

            if (output.sublist(1) != P_km.sublist(1)
                ? output.hex == P_km.sublist(1).hex
                : output.sublist(1).hex == P_km.sublist(1).hex) {
              // - Add P_km to the wallet
              matches[output.hex] = [
                PrivateKey.fromBytes(curve, t_k).tweakAdd(tweak.fromHex.bigint)!.toCompressedHex(),
                tweak
              ];
              outputPubKeys.removeAt(i);
              k++; // Increment counter
              return true;
            }
            return false;
          });

          if (found) {
            break;
          }
        }
      }

      outputPubKeys.removeAt(i);

      if (i + 1 >= outputPubKeys.length) {
        break;
      }
    }
  } while (outputPubKeys.isNotEmpty);

  return matches;
}
