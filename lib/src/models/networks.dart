import 'dart:typed_data';
import '../payments/address/core.dart';
import '../formatting/bytes_num_formatting.dart';

enum BtcNetwork { mainnet, testnet }

class NetworkInfo {
  final String messagePrefix;
  final String bech32;
  final int p2pkhPrefix;
  final int p2shPrefix;
  final int wif;
  final BtcNetwork network;
  final Map<AddressType, String> extendPrivate;
  final Map<AddressType, String> extendPublic;
  bool get isMainnet => network == BtcNetwork.mainnet;

  /// ignore: constant_identifier_names
  static const BITCOIN = NetworkInfo(
      network: BtcNetwork.mainnet,
      messagePrefix: '\x18Bitcoin Signed Message:\n',
      bech32: 'bc',
      p2pkhPrefix: 0x00,
      p2shPrefix: 0x05,
      wif: 0x80,
      extendPrivate: {
        AddressType.p2pkh: "0x0488ade4",
        AddressType.p2pkhInP2sh: "0x0488ade4",
        AddressType.p2wpkh: "0x04b2430c",
        AddressType.p2wpkhInP2sh: "0x049d7878",
        AddressType.p2wsh: "0x02aa7a99",
        AddressType.p2wshInP2sh: "0x0295b005"
      },
      extendPublic: {
        AddressType.p2pkh: "0x0488b21e",
        AddressType.p2pkhInP2sh: "0x0488b21e",
        AddressType.p2wpkh: "0x04b24746",
        AddressType.p2wpkhInP2sh: "0x049d7cb2",
        AddressType.p2wsh: "0x02aa7ed3",
        AddressType.p2wshInP2sh: "0x0295b43f"
      });

  /// ignore: constant_identifier_names
  static const TESTNET = NetworkInfo(
      network: BtcNetwork.testnet,
      messagePrefix: '\x18Bitcoin Signed Message:\n',
      bech32: 'tb',
      p2pkhPrefix: 0x6f,
      p2shPrefix: 0xc4,
      wif: 0xef,
      extendPrivate: {
        AddressType.p2pkh: "0x04358394",
        AddressType.p2pkhInP2sh: "0x04358394",
        AddressType.p2wpkh: "0x045f18bc",
        AddressType.p2wpkhInP2sh: "0x044a4e28",
        AddressType.p2wsh: "0x02575048",
        AddressType.p2wshInP2sh: "0x024285b5"
      },
      extendPublic: {
        AddressType.p2pkh: "0x043587cf",
        AddressType.p2pkhInP2sh: "0x043587cf",
        AddressType.p2wpkh: "0x045f1cf6",
        AddressType.p2wpkhInP2sh: "0x044a5262",
        AddressType.p2wsh: "0x02575483",
        AddressType.p2wshInP2sh: "0x024289ef"
      });
  static NetworkInfo networkFromWif(String wif) {
    final w = int.parse(wif, radix: 16);
    if (TESTNET.wif == w) {
      return TESTNET;
    } else if (BITCOIN.wif == w) {
      return BITCOIN;
    }
    throw ArgumentError("wif perefix $wif not supported, only bitcoin or testnet accepted");
  }

  static AddressType? networkFromXPrivePrefix(Uint8List prefix) {
    final w = "0x${bytesToHex(prefix)}";
    if (TESTNET.extendPrivate.values.contains(w)) {
      return TESTNET.extendPrivate.keys
          .firstWhere((element) => TESTNET.extendPrivate[element] == w);
    } else if (BITCOIN.extendPrivate.values.contains(w)) {
      return BITCOIN.extendPrivate.keys
          .firstWhere((element) => BITCOIN.extendPrivate[element] == w);
    }
    return null;
  }

  static AddressType? networkFromXPublicPrefix(Uint8List prefix) {
    final w = "0x${bytesToHex(prefix)}";
    if (TESTNET.extendPublic.values.contains(w)) {
      return TESTNET.extendPublic.keys.firstWhere((element) => TESTNET.extendPublic[element] == w);
    } else if (BITCOIN.extendPublic.values.contains(w)) {
      return BITCOIN.extendPublic.keys.firstWhere((element) => BITCOIN.extendPublic[element] == w);
    }
    return null;
  }

  const NetworkInfo(
      {required this.messagePrefix,
      required this.bech32,
      required this.p2pkhPrefix,
      required this.p2shPrefix,
      required this.wif,
      required this.extendPrivate,
      required this.extendPublic,
      required this.network});
}

class NetworkType {
  String messagePrefix;
  String bech32;
  Bip32Type bip32;
  int pubKeyHash;
  int scriptHash;
  int wif;

  NetworkType(
      {required this.messagePrefix,
      String? bech32,
      required this.bip32,
      required this.pubKeyHash,
      required this.scriptHash,
      required this.wif})
      : this.bech32 = bech32 ?? '';

  @override
  String toString() {
    return 'NetworkType{messagePrefix: $messagePrefix, bech32: $bech32, bip32: ${bip32.toString()}, pubKeyHash: $pubKeyHash, scriptHash: $scriptHash, wif: $wif}';
  }
}

class Bip32Type {
  int public;
  int private;

  Bip32Type({required this.public, required this.private});

  @override
  String toString() {
    return 'Bip32Type{public: $public, private: $private}';
  }
}

final bitcoin = new NetworkType(
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: new Bip32Type(public: 0x0488b21e, private: 0x0488ade4),
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80);

final testnet = new NetworkType(
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: new Bip32Type(public: 0x043587cf, private: 0x04358394),
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef);
