import 'package:bitcoin_flutter/bitcoin_flutter.dart';
import 'package:test/test.dart';
import 'package:bip39/bip39.dart' as bip39;

void main() {
  group('recoverable signatures (HDWallet)', () {
    var seed = bip39.mnemonicToSeed(
        'praise you muffin lion enable neck grocery crumble super myself license ghost');
    HDWallet hdWallet = new HDWallet.fromSeed(seed);

    test('signature has a valid v', () {
      final sig = hdWallet.signMessage("cakewallet is awesome");
      expect(sig[0], 31);
    });
  });
}
