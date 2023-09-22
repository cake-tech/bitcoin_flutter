import 'dart:typed_data';

import 'package:bitcoin_flutter/src/templates/silentpaymentaddress.dart';
import 'package:coinlib/coinlib.dart';
import '../utils/uint8list.dart';

Map<String, List<ECPublicKey>> generateMultipleRecipientPubkeys(
    ECPrivateKey sum, Uint8List outpointHash, List<String> recipientAddresses) {
  Map<ECPublicKey, (ECPublicKey, List<SilentPaymentReceiver>)> silentPaymentGroups = {};

  for (final address in recipientAddresses) {
    final silentPaymentAddress = SilentPaymentReceiver.fromString(address);
    final scanKey = silentPaymentAddress.scanPubkey;

    if (silentPaymentGroups.containsKey(scanKey)) {
      final (ecdhSharedSecret, recipients) = silentPaymentGroups[scanKey]!;
      silentPaymentGroups[scanKey] = (ecdhSharedSecret, [...recipients, silentPaymentAddress]);
    } else {
      final ecdhSharedSecret =
          scanKey.mul(outpointHash, compress: true)!.mul(sum.data, compress: true)!;
      silentPaymentGroups[scanKey] = (ecdhSharedSecret, [silentPaymentAddress]);
    }
  }

  Map<String, List<ECPublicKey>> result = {};
  for (final group in silentPaymentGroups.entries) {
    final (ecdhSharedSecret, recipients) = group.value;

    int n = 0;
    for (final recipient in recipients) {
      final tweak = sha256Hash(ecdhSharedSecret.data.concat([serialiseUint32(n)]));

      final res = ECPublicKey(recipient.spendPubkey.data).tweak(tweak)!;

      if (result.containsKey(recipient.toString())) {
        result[recipient.toString()]!.add(res);
      } else {
        result[recipient.toString()] = [res];
      }
      n++;
    }
  }

  return result;
}

Uint8List serialiseUint32(int n) {
  Uint8List buf = Uint8List(4);
  ByteData byteData = ByteData.view(buf.buffer);
  byteData.setUint32(0, n, Endian.big);
  return buf;
}
