import 'dart:typed_data';

import '../bitcoin_flutter_base.dart';
import '../utils/constants/derivation_paths.dart';
import '../utils/string.dart';
import '../utils/uint8list.dart';
import 'package:elliptic/elliptic.dart';
import 'package:dart_bech32/dart_bech32.dart';
import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;

class SilentPaymentReceiver extends SilentPaymentAddress {
  late int version;
  late PublicKey scanPubkey;
  late PublicKey spendPubkey;
  late String hrp;

  late PrivateKey scanPrivkey;
  late PrivateKey spendPrivkey;

  SilentPaymentReceiver({
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

  factory SilentPaymentReceiver.fromHd(HDWallet hd, {String? hrp, int? version}) {
    final scanPubkey = hd.derivePath(SCAN_PATH);
    final spendPubkey = hd.derivePath(SPEND_PATH);

    final curve = getSecp256k1();

    return SilentPaymentReceiver(
      scanPrivkey: PrivateKey.fromBytes(curve, scanPubkey.privKey!.fromHex),
      spendPrivkey: PrivateKey.fromBytes(curve, spendPubkey.privKey!.fromHex),
      scanPubkey: PublicKey.fromHex(curve, scanPubkey.pubKey!),
      spendPubkey: PublicKey.fromHex(curve, spendPubkey.pubKey!),
      hrp: hrp ?? 'sp',
      version: version ?? 0,
    );
  }

  factory SilentPaymentReceiver.fromMnemonic(String mnemonic, {String? hrp, int? version}) {
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

    final curve = getSecp256k1();

    return SilentPaymentReceiver(
      scanPrivkey: PrivateKey.fromBytes(curve, scanPubkey.privateKey!),
      spendPrivkey: PrivateKey.fromBytes(curve, spendPubkey.privateKey!),
      scanPubkey: PublicKey.fromHex(curve, scanPubkey.publicKey.hex),
      spendPubkey: PublicKey.fromHex(curve, spendPubkey.publicKey.hex),
      hrp: hrp ?? 'sp',
      version: version ?? 0,
    );
  }
}

class SilentPaymentDestination extends SilentPaymentAddress {
  SilentPaymentDestination({
    required int version,
    required PublicKey scanPubkey,
    required PublicKey spendPubkey,
    required String hrp,
    required this.amount,
  }) : super(version: version, scanPubkey: scanPubkey, spendPubkey: spendPubkey, hrp: hrp);

  int amount;

  factory SilentPaymentDestination.fromAddress(String address, int amount) {
    final receiver = SilentPaymentAddress.fromString(address);

    return SilentPaymentDestination(
      scanPubkey: receiver.scanPubkey,
      spendPubkey: receiver.spendPubkey,
      hrp: receiver.hrp,
      version: receiver.version,
      amount: amount,
    );
  }
}

class SilentPaymentAddress {
  int version;
  PublicKey scanPubkey;
  PublicKey spendPubkey;
  // human readable part (sprt, sp, tsp)
  String hrp;

  SilentPaymentAddress({
    required this.version,
    required this.scanPubkey,
    required this.spendPubkey,
    required this.hrp,
  }) {
    if (version != 0) {
      throw Exception("Can't have other version than 0 for now");
    }
  }

  factory SilentPaymentAddress.fromString(String address) {
    final decoded = bech32m.decode(address, 1023);

    final prefix = decoded.prefix;
    if (prefix != 'sp' && prefix != 'sprt' && prefix != 'tsp') {
      throw Exception('Invalid prefix: $prefix');
    }

    final words = decoded.words.sublist(1);
    final version = words[0];
    if (version != 0) throw new ArgumentError('Invalid version');

    final key = bech32m.fromWords(words);
    final curve = getSecp256k1();

    return SilentPaymentAddress(
      scanPubkey: PublicKey.fromHex(curve, key.sublist(0, 33).hex),
      spendPubkey: PublicKey.fromHex(curve, key.sublist(33).hex),
      hrp: prefix,
      version: version,
    );
  }

  factory SilentPaymentAddress.createLabeledSilentPaymentAddress(
      PublicKey scanPubKey, PublicKey spendPubKey, Uint8List m,
      {String hrp = 'sp', int version = 0}) {
    final tweakedSpendKey = spendPubKey.tweakAdd(m.bigint);
    return SilentPaymentAddress(
        scanPubkey: scanPubKey, spendPubkey: tweakedSpendKey, hrp: hrp, version: version);
  }

  @override
  String toString() {
    final data = bech32m.toWords(Uint8List.fromList(
        [...scanPubkey.toCompressedHex().fromHex, ...spendPubkey.toCompressedHex().fromHex]));
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
