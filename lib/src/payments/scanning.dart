import 'dart:typed_data';
import 'package:bitcoin_flutter/src/payments/silentpayments.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:elliptic/elliptic.dart';
import 'package:crypto/crypto.dart';
import '../utils/uint8list.dart';

Uint8List? handleLabels(
  Uint8List output,
  Uint8List tweakedPublicKey,
  Uint8List tweak,
  Map<String, String> labels,
) {
  final curve = getSecp256k1();

  final negatedPublicKey = PublicKey.fromHex(curve, tweakedPublicKey.hex).negate();
  final newNegatedPubKey = PublicKey.fromHex(curve, negatedPublicKey.toCompressedHex());
  final newOutput = PublicKey.fromHex(curve, output.hex);

  final mG = PublicKey.fromPoint(curve, curve.add(newOutput, newNegatedPubKey));

  var labelHex = labels[mG.toCompressedHex()];

  if (labelHex == null) {
    final negatedOutput =
        PublicKey.fromHex(curve, PublicKey.fromHex(curve, output.hex).negate().toCompressedHex());
    final new_mG = PublicKey.fromPoint(curve, curve.add(negatedOutput, newNegatedPubKey));
    labelHex = labels[new_mG.toCompressedHex()];
  }

  if (labelHex != null) {
    return PrivateKey.fromHex(curve, tweak.hex)
        .tweakAdd(labelHex.fromHex.bigint)!
        .toCompressedHex()
        .fromHex;
  }

  return null;
}

int processTweak(Uint8List spendPublicKey, Uint8List tweak, List<Uint8List> outputPubKeys,
    Map<String, Uint8List> matches,
    {Map<String, String>? labels}) {
  final curve = getSecp256k1();
  final tweakedPublicKey =
      PublicKey.fromHex(curve, spendPublicKey.hex).tweakAdd(tweak.bigint).toCompressedHex().fromHex;

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
  final curve = getSecp256k1();
  final ecdhSecret = PublicKey.fromHex(curve, sumOfInputPublicKeys.hex).tweakMul(
    PrivateKey.fromHex(curve, scanPrivateKey.hex)
        .tweakMul(outpointHash.bigint)!
        .toCompressedHex()
        .fromHex
        .bigint,
  );

  // output-to-tweak data map
  final matches = <String, Uint8List>{};

  var n = 0;
  var counterIncrement = 0;
  do {
    final tweak = sha256
        .convert(ecdhSecret!.toCompressedHex().fromHex.concat([serialiseUint32(n)]))
        .toString();
    counterIncrement =
        processTweak(spendPublicKey, tweak.fromHex, outputPubKeys, matches, labels: labels);
    n += counterIncrement;
  } while (counterIncrement > 0 && outputPubKeys.isNotEmpty);

  return matches;
}
