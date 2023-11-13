import 'package:bitcoin_flutter/bitcoin_flutter.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:elliptic/elliptic.dart';
import 'package:bitcoin_base/bitcoin_base.dart' as bitcoin_base;

class PrivateKeyInfo {
  final PrivateKey key;
  final bool isTaproot;

  PrivateKeyInfo(this.key, this.isTaproot);
}

PrivateKey getSumInputPrivKeys(List<PrivateKeyInfo> senderSecretKeys) {
  List<PrivateKey> negatedKeys = [];

  for (final info in senderSecretKeys) {
    final key = info.key;
    final isTaproot = info.isTaproot;

    if (isTaproot && key.toCompressedHex().fromHex[0] == 0x03) {
      negatedKeys.add(key.negate()!);
    } else {
      negatedKeys.add(key);
    }
  }

  final head = negatedKeys.first;
  final tail = negatedKeys.sublist(1);

  final result = tail.fold<PrivateKey>(
    head,
    (acc, item) => acc.tweakAdd(item.toCompressedHex().fromHex.bigint)!,
  );

  return result;
}

bitcoin_base.P2trAddress getTaproot(String address) {
  return bitcoin_base.P2trAddress(program: address);
}

List<dynamic> getScript(String raw) {
  return bitcoin_base.Script.fromRaw(hexData: raw, hasSegwit: true).script;
}
