import 'dart:typed_data';

import 'package:coinlib/coinlib.dart';
import 'package:dart_bech32/dart_bech32.dart';
import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;

class SilentPaymentAddress extends SilentPaymentReceiver {
  late int version;
  late ECPublicKey scanPubkey;
  late ECPublicKey spendPubkey;
  late bool isTestnet;

  late ECPrivateKey scanPrivkey;
  late ECPrivateKey spendPrivkey;

  SilentPaymentAddress({
    required this.version,
    required this.scanPubkey,
    required this.spendPubkey,
    required this.isTestnet,
    required this.scanPrivkey,
    required this.spendPrivkey,
  }) : super(
          version: version,
          scanPubkey: scanPubkey,
          spendPubkey: spendPubkey,
          isTestnet: isTestnet,
        );

  static SilentPaymentAddress fromMnemonic(String mnemonic, {bool? isTestnet, int? version}) {
    final seed = bip39.mnemonicToSeed(mnemonic);
    final root = BIP32.fromSeed(seed);
    if (root.depth != 0 || root.parentFingerprint != 0) throw new ArgumentError('Bad master key!');

    final scanPubkey = root.derivePath("m/352'/0'/0'/1'/0'");
    final spendPubkey = root.derivePath("m/352'/0'/0'/0'/0'");

    return SilentPaymentAddress(
      scanPrivkey: ECPrivateKey(scanPubkey.privateKey!),
      spendPrivkey: ECPrivateKey(spendPubkey.privateKey!),
      scanPubkey: ECPublicKey(scanPubkey.publicKey),
      spendPubkey: ECPublicKey(spendPubkey.publicKey),
      isTestnet: isTestnet ?? false,
      version: version ?? 0,
    );
  }
}

class SilentPaymentReceiver {
  late int version;
  late ECPublicKey scanPubkey;
  late ECPublicKey spendPubkey;
  late bool isTestnet;

  SilentPaymentReceiver({
    required this.version,
    required this.scanPubkey,
    required this.spendPubkey,
    required this.isTestnet,
  }) {
    if (version != 0) {
      throw Exception("Can't have other version than 0 for now");
    }
  }

  static fromString(String address) {
    final decoded = bech32m.decode(address, 1023);

    final prefix = decoded.prefix;
    if (prefix != 'sprt' && prefix != 'tsp') {
      throw Exception('Invalid prefix: $prefix');
    }

    final words = decoded.words.sublist(1);
    final version = words[0];
    if (version != 0) throw new ArgumentError('Invalid version');

    final key = bech32m.fromWords(words);

    return SilentPaymentReceiver(
      scanPubkey: ECPublicKey(key.sublist(0, 33)),
      spendPubkey: ECPublicKey(key.sublist(33)),
      isTestnet: prefix == 'tsp',
      version: version,
    );
  }

  @override
  String toString() {
    final hrp = isTestnet ? 'tsp' : 'sprt';

    final data = bech32m.toWords(Uint8List.fromList([...scanPubkey.data, ...spendPubkey.data]));
    final versionData = Uint8List.fromList([Bech32U5(version).value, ...data]);

    return bech32m.encode(Decoded(prefix: hrp, words: versionData, limit: 1180));
  }
}

class Bech32U5 {
  final int value;

  Bech32U5(this.value) {
    if (value < 0 || value > 31) {
      throw Exception('Value is outside the valid range.');
    }
  }

  static Bech32U5 tryFromInt(int value) {
    if (value < 0 || value > 31) {
      throw Exception('Value is outside the valid range.');
    }
    return Bech32U5(value);
  }
}
