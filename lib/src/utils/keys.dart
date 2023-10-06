import 'dart:typed_data';

import 'package:coinlib/coinlib.dart';
import 'package:bitcoin_base/bitcoin_base.dart' as bitcoin_base;

class PrivateKeyInfo {
  final ECPrivateKey key;
  final bool isTaproot;

  PrivateKeyInfo(this.key, this.isTaproot);
}

ECPrivateKey getSumInputPrivKeys(List<PrivateKeyInfo> senderSecretKeys) {
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

bitcoin_base.P2trAddress getTaproot(String address) {
  return bitcoin_base.P2trAddress(program: address);
}

List<dynamic> getScript(String raw) {
  return bitcoin_base.Script.fromRaw(hexData: raw, hasSegwit: true).script;
}
