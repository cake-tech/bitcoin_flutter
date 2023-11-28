import 'dart:typed_data';
import '../payments/address/core.dart';
import '../formatting/bytes_num_formatting.dart';

enum BtcNetwork { mainnet, testnet }

class Bip32Type {
  final int public;
  final int private;

  const Bip32Type({required this.public, required this.private});

  @override
  String toString() {
    return 'Bip32Type{public: $public, private: $private}';
  }
}

class NetworkType {
  final String messagePrefix;
  final String bech32;
  final Bip32Type bip32;
  final int pubKeyHash;
  final int scriptHash;
  final int wif;
  final int p2pkhPrefix;
  final int p2shPrefix;
  final BtcNetwork network;
  final Map<AddressType, String> extendPrivate;
  final Map<AddressType, String> extendPublic;
  bool get isMainnet => network == BtcNetwork.mainnet;

  const NetworkType(
      {required this.messagePrefix,
      String? bech32,
      required this.bip32,
      required this.pubKeyHash,
      required this.scriptHash,
      required this.wif,
      required this.p2pkhPrefix,
      required this.p2shPrefix,
      required this.extendPrivate,
      required this.extendPublic,
      required this.network})
      : this.bech32 = bech32 ?? '';

  static const BITCOIN = NetworkType(
      messagePrefix: '\x18Bitcoin Signed Message:\n',
      bech32: 'bc',
      bip32: const Bip32Type(public: 0x0488b21e, private: 0x0488ade4),
      pubKeyHash: 0x00,
      scriptHash: 0x05,
      wif: 0x80,
      network: BtcNetwork.mainnet,
      p2pkhPrefix: 0x00,
      p2shPrefix: 0x05,
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

  static const TESTNET = NetworkType(
      messagePrefix: '\x18Bitcoin Signed Message:\n',
      bech32: 'tb',
      bip32: const Bip32Type(public: 0x043587cf, private: 0x04358394),
      pubKeyHash: 0x6f,
      scriptHash: 0xc4,
      wif: 0xef,
      network: BtcNetwork.testnet,
      p2pkhPrefix: 0x6f,
      p2shPrefix: 0xc4,
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

  static NetworkType networkFromWif(String wif) {
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

  @override
  String toString() {
    return 'NetworkType{messagePrefix: $messagePrefix, bech32: $bech32, bip32: ${bip32.toString()}, pubKeyHash: $pubKeyHash, scriptHash: $scriptHash, wif: $wif}';
  }
}

final bitcoin = NetworkType.BITCOIN;
final testnet = NetworkType.TESTNET;
