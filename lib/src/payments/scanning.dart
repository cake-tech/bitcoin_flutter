import 'dart:typed_data';
import 'package:bitcoin_flutter/src/payments/silentpayments.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:coinlib/coinlib.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import '../utils/uint8list.dart';

Uint8List? handleLabels(
  Uint8List output,
  Uint8List tweakedPublicKey,
  Uint8List tweak,
  Map<String, String> labels,
) {
  final secp256k1 = elliptic.getSecp256k1();

  final negatedPublicKey = ECPublicKey(tweakedPublicKey).negate(compress: true)!;
  final newNegatedPubKey = elliptic.PublicKey.fromHex(secp256k1, negatedPublicKey.data.hex);
  final newOutput = elliptic.PublicKey.fromHex(secp256k1, output.hex);

  final mG = elliptic.PublicKey.fromPoint(
      secp256k1, elliptic.getSecp256k1().add(newOutput, newNegatedPubKey));

  var labelHex = labels[mG.toCompressedHex()];

  if (labelHex == null) {
    final negatedOutput =
        elliptic.PublicKey.fromHex(secp256k1, ECPublicKey(output).negate(compress: true)!.data.hex);
    final new_mG = elliptic.PublicKey.fromPoint(
        secp256k1, elliptic.getSecp256k1().add(negatedOutput, newNegatedPubKey));
    labelHex = labels[new_mG.toCompressedHex()];
  }

  if (labelHex != null) {
    return ECPrivateKey(tweak).tweak(labelHex.fromHex)!.data;
  }

  return null;
}

int processTweak(Uint8List spendPublicKey, Uint8List tweak, List<Uint8List> outputPubKeys,
    Map<String, Uint8List> matches,
    {Map<String, String>? labels}) {
  final tweakedPublicKey = ECPublicKey(spendPublicKey).tweak(tweak)!.data;

  for (var i = 0; i < outputPubKeys.length; i++) {
    final output = outputPubKeys[i];

    if (output.sublist(1).toString() == tweakedPublicKey.sublist(1).toString()) {
      // Found the tweak, this output is ours and the tweak can be used to derive the private key
      matches[output.hex] = tweak;
      outputPubKeys.removeAt(i);
      return 1; // Increment counter
    }

    if (labels != null) {
      // Additional logic if labels are provided
      final privateKeyTweak = handleLabels(output, tweakedPublicKey, tweak, labels);
      if (privateKeyTweak != null) {
        matches[output.hex] = privateKeyTweak;
        return 1; // Increment counter
      }
    }
  }

  return 0; // No counter increment
}

Map<String, Uint8List> scanOutputs(Uint8List scanPrivateKey, Uint8List spendPublicKey,
    Uint8List sumOfInputPublicKeys, Uint8List outpointHash, List<Uint8List> outputPubKeys,
    {Map<String, String>? labels}) {
  final ecdhSecret = ECPublicKey(sumOfInputPublicKeys)
      .mul(ECPrivateKey(scanPrivateKey).mul(outpointHash)!.data, compress: true);

  // output-to-tweak data map
  final matches = <String, Uint8List>{};

  var n = 0;
  var counterIncrement = 0;
  do {
    final tweak = sha256Hash(ecdhSecret!.data.concat([serialiseUint32(n)]));
    counterIncrement = processTweak(spendPublicKey, tweak, outputPubKeys, matches, labels: labels);
    n += counterIncrement;
  } while (counterIncrement > 0 && outputPubKeys.isNotEmpty);

  return matches;
}
