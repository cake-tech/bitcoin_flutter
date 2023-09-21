import 'package:coinlib/coinlib.dart';

typedef PrivateKeyInfo = (ECPrivateKey, bool);

List<PrivateKeyInfo> decodePrivateKeys(List<(String, bool)> inputPrivKeys) {
  return inputPrivKeys.map((input) => (ECPrivateKey.fromHex(input.$1), input.$2)).toList();
}

ECPrivateKey getSumInputPrivKeys(List<PrivateKeyInfo> senderSecretKeys) {
  List<ECPrivateKey> negatedKeys = [];

  for (final info in senderSecretKeys) {
    final (key, isTaproot) = info;

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
