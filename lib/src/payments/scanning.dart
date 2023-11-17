import 'dart:typed_data';
import 'package:bitcoin_flutter/src/payments/silentpayments.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:elliptic/elliptic.dart';
import 'package:crypto/crypto.dart';
import '../utils/uint8list.dart';
import '../ec/ec_public.dart';
import '../models/networks.dart';
import '../payments/address/segwit_address.dart';

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

int processTweak(Uint8List spendPublicKey, Uint8List tweak, List<String> outputP2trAddresses,
    Map<String, Uint8List> matches,
    {Map<String, String>? labels}) {
  final curve = getSecp256k1();

  // pubkey generated from tweak
  final tweakedPublicKey = PublicKey.fromHex(curve, spendPublicKey.hex).tweakAdd(tweak.bigint);
  final tweakedPublicKeyBytes = tweakedPublicKey.toCompressedHex().fromHex;

  final tapPoint = ECPublic.fromHex(tweakedPublicKey.toHex()).toTapPoint();
  // taproot address result from tweaked pubkey
  final tweakedP2trAddress = P2trAddress(program: tapPoint).toAddress(NetworkInfo.TESTNET);

  for (var i = 0; i < outputP2trAddresses.length; i++) {
    // the taproot adress being paid to in the output to check
    final outputAddress = outputP2trAddresses[i];

    if (outputAddress == tweakedP2trAddress) {
      // Found the tweak, this output is ours and the tweak can be used to derive the private key
      matches[outputAddress] = tweak;
      outputP2trAddresses.removeAt(i);
      return 1; // Increment counter
    }

    if (labels != null) {
      // Additional logic if labels are provided
      final privateKeyTweak =
          handleLabels(tweakedPublicKeyBytes, tweakedPublicKeyBytes, tweak, labels);
      if (privateKeyTweak != null) {
        matches[outputAddress] = privateKeyTweak;
        return 1; // Increment counter
      }
    }
  }

  return 0; // No counter increment
}

Map<String, Uint8List> scanOutputs(Uint8List scanPrivateKey, Uint8List spendPublicKey,
    Uint8List sumOfInputPublicKeys, Uint8List outpointHash, List<String> outputP2trAddresses,
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
        processTweak(spendPublicKey, tweak.fromHex, outputP2trAddresses, matches, labels: labels);
    n += counterIncrement;
  } while (counterIncrement > 0 && outputP2trAddresses.isNotEmpty);

  return matches;
}
