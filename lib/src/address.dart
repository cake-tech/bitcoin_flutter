import 'dart:typed_data';
import 'package:bip32/bip32.dart';
import 'package:bip32/src/utils/ecurve.dart' as ecc;
import 'models/networks.dart' as network_model;
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:bech32/bech32.dart';
import 'payments/index.dart' show PaymentData;
import 'payments/p2pkh.dart';
import 'payments/p2wpkh.dart';
import 'package:dart_bech32/dart_bech32.dart';

class Address {
  static bool validateAddress(String address, [network_model.NetworkType? nw]) {
    try {
      addressToOutputScript(address, nw);
      return true;
    } catch (err) {
      return false;
    }
  }

  static Uint8List addressToOutputScript(String address, [network_model.NetworkType? nw]) {
    network_model.NetworkType network = nw ?? network_model.bitcoin;
    var decodeBase58;
    var decodeBech32;
    try {
      decodeBase58 = bs58check.decode(address);
    } catch (err) {}
    if (decodeBase58 != null) {
      if (decodeBase58[0] != network.pubKeyHash)
        throw new ArgumentError('Invalid version or Network mismatch');
      P2PKH p2pkh = new P2PKH(data: new PaymentData(address: address), network: network);
      return p2pkh.data.output!;
    } else {
      try {
        decodeBech32 = segwit.decode(address);
      } catch (err) {}
      if (decodeBech32 != null) {
        if (network.bech32 != decodeBech32.hrp)
          throw new ArgumentError('Invalid prefix or Network mismatch');
        if (decodeBech32.version != 0) throw new ArgumentError('Invalid address version');
        P2WPKH p2wpkh = new P2WPKH(data: new PaymentData(address: address), network: network);
        return p2wpkh.data.output!;
      }
    }
    throw new ArgumentError(address + ' has no matching Script');
  }

  static Map<String, BIP32> deriveSilentPaymentsKeyPair(BIP32 root) {
    if (root.depth != 0 || root.parentFingerprint != 0) throw new ArgumentError('Bad master key!');

    return {
      'scanKey': root.derivePath("m/352'/0'/0'/1'/0'"),
      'spendKey': root.derivePath("m/352'/0'/0'/0'/0'"),
    };
  }

  static String encodeSilentPaymentAddress(Uint8List scanKey, Uint8List spendKey,
      {String hrp = 'tsp', int version = 0}) {
    Uint8List data = bech32m.toWords(Uint8List.fromList([...scanKey, ...spendKey]));
    Uint8List versionData = Uint8List.fromList([version, ...data]);

    return bech32m.encode(Decoded(prefix: hrp, words: versionData, limit: 1180));
  }

  static Map<String, Uint8List> decodeSilentPaymentAddress(String address, {String hrp = 'tsp'}) {
    final decoded = bech32m.decode(address, 1023);

    final prefix = decoded.prefix;
    if (prefix != hrp) throw new ArgumentError('Invalid prefix');

    final words = decoded.words.sublist(1);
    final version = words[0];
    if (version != 0) throw new ArgumentError('Invalid version');

    final key = bech32m.fromWords(words);

    return {'scanKey': key.sublist(0, 33), 'spendKey': key.sublist(33)};
  }
}
