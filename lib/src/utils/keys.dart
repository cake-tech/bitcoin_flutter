import 'package:elliptic/elliptic.dart';

class PrivateKeyInfo {
  final PrivateKey key;
  final bool isTaproot;

  PrivateKeyInfo(this.key, this.isTaproot);
}

PublicKey getSumInputPubKeys(List<String> pubkeys) {
  final curve = getSecp256k1();
  List<PublicKey> negatedKeys = [];

  for (final info in pubkeys) {
    negatedKeys.add(PublicKey.fromHex(curve, info));

    // if (isTaproot && key.toCompressedHex().fromHex[0] == 0x03) {
    //   negatedKeys.add(PublicKey(getSecp256k1(), key.X, key.Y).negate()!);
    // } else {
    //   negatedKeys.add(key);
    // }
  }

  final head = negatedKeys.first;
  final tail = negatedKeys.sublist(1);

  final result = tail.fold<PublicKey>(
    head,
    (acc, item) => PublicKey(getSecp256k1(), acc.X, acc.Y).pubkeyAdd(item),
  );

  return result;
}
