import 'dart:typed_data';

import 'package:bitcoin_flutter/bitcoin_flutter.dart';
import 'package:bitcoin_flutter/src/utils/constants/derivation_paths.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:coinlib/coinlib.dart';
import 'package:dart_bech32/dart_bech32.dart';
import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;

class SilentPaymentAddress extends SilentPaymentReceiver {
  late int version;
  late ECPublicKey scanPubkey;
  late ECPublicKey spendPubkey;
  late String hrp;

  late ECPrivateKey scanPrivkey;
  late ECPrivateKey spendPrivkey;

  SilentPaymentAddress({
    required this.version,
    required this.scanPubkey,
    required this.spendPubkey,
    required this.hrp,
    required this.scanPrivkey,
    required this.spendPrivkey,
  }) : super(
          version: version,
          scanPubkey: scanPubkey,
          spendPubkey: spendPubkey,
          hrp: hrp,
        );

  static Future<SilentPaymentAddress> fromHd(HDWallet hd, {String? hrp, int? version}) async {
    await loadCoinlib();

    final scanPubkey = hd.derivePath(SCAN_PATH);
    final spendPubkey = hd.derivePath(SPEND_PATH);

    return SilentPaymentAddress(
      scanPrivkey: ECPrivateKey(scanPubkey.privKey!.fromHex),
      spendPrivkey: ECPrivateKey(spendPubkey.privKey!.fromHex),
      scanPubkey: ECPublicKey(scanPubkey.pubKey!.fromHex),
      spendPubkey: ECPublicKey(spendPubkey.pubKey!.fromHex),
      hrp: hrp ?? 'sp',
      version: version ?? 0,
    );
  }

  static Future<SilentPaymentAddress> fromMnemonic(String mnemonic,
      {String? hrp, int? version}) async {
    await loadCoinlib();

    final seed = bip39.mnemonicToSeed(mnemonic);
    final root = bip32.BIP32.fromSeed(
        seed,
        hrp == "tsp"
            ? bip32.NetworkType(
                wif: 0xef, bip32: new bip32.Bip32Type(public: 0x043587cf, private: 0x04358394))
            : null);
    if (root.depth != 0 || root.parentFingerprint != 0) throw new ArgumentError('Bad master key!');

    final scanPubkey = root.derivePath(SCAN_PATH);
    final spendPubkey = root.derivePath(SPEND_PATH);

    return SilentPaymentAddress(
      scanPrivkey: ECPrivateKey(scanPubkey.privateKey!),
      spendPrivkey: ECPrivateKey(spendPubkey.privateKey!),
      scanPubkey: ECPublicKey(scanPubkey.publicKey),
      spendPubkey: ECPublicKey(spendPubkey.publicKey),
      hrp: hrp ?? 'sp',
      version: version ?? 0,
    );
  }
}

class SilentPaymentDestination extends SilentPaymentReceiver {
  SilentPaymentDestination({
    required int version,
    required ECPublicKey scanPubkey,
    required ECPublicKey spendPubkey,
    required String hrp,
    required this.amount,
  }) : super(version: version, scanPubkey: scanPubkey, spendPubkey: spendPubkey, hrp: hrp);

  int amount;

  factory SilentPaymentDestination.fromAddress(String address, int amount) {
    final receiver = SilentPaymentReceiver.fromString(address);

    return SilentPaymentDestination(
      scanPubkey: receiver.scanPubkey,
      spendPubkey: receiver.spendPubkey,
      hrp: receiver.hrp,
      version: receiver.version,
      amount: amount,
    );
  }
}

class SilentPaymentReceiver {
  late int version;
  late ECPublicKey scanPubkey;
  late ECPublicKey spendPubkey;
  // human readable part (sprt, sp, tsp)
  late String hrp;

  SilentPaymentReceiver({
    required this.version,
    required this.scanPubkey,
    required this.spendPubkey,
    required this.hrp,
  }) {
    if (version != 0) {
      throw Exception("Can't have other version than 0 for now");
    }
  }

  factory SilentPaymentReceiver.fromString(String address) {
    final decoded = bech32m.decode(address, 1023);

    final prefix = decoded.prefix;
    if (prefix != 'sp' && prefix != 'sprt' && prefix != 'tsp') {
      throw Exception('Invalid prefix: $prefix');
    }

    final words = decoded.words.sublist(1);
    final version = words[0];
    if (version != 0) throw new ArgumentError('Invalid version');

    final key = bech32m.fromWords(words);

    return SilentPaymentReceiver(
      scanPubkey: ECPublicKey(key.sublist(0, 33)),
      spendPubkey: ECPublicKey(key.sublist(33)),
      hrp: prefix,
      version: version,
    );
  }

  factory SilentPaymentReceiver.createLabeledSilentPaymentAddress(
      ECPublicKey scanPubKey, ECPublicKey spendPubKey, Uint8List m,
      {String hrp = 'sp', int version = 0}) {
    final tweakedSpendKey = spendPubKey.tweak(m, compress: true);
    return SilentPaymentReceiver(
        scanPubkey: scanPubKey, spendPubkey: tweakedSpendKey!, hrp: hrp, version: version);
  }

  @override
  String toString() {
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
