import 'dart:typed_data';

import 'core.dart';
import 'package:bitcoin_flutter/src/payments/script/script.dart';
import '../tools/tools.dart';
import '../constants/constants.dart';
import 'package:bitcoin_flutter/src/models/networks.dart';
import '../../utils/string.dart';
import '../../utils/uint8list.dart';
import '../../utils/constants/op.dart';
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:bitcoin_flutter/src/utils/script.dart' as bscript;

abstract class BipAddress implements BitcoinAddress {
  /// Represents a Bitcoin address
  ///
  /// [hash160] the hash160 string representation of the address; hash160 represents
  /// two consequtive hashes of the public key or the redeem script, first
  /// a SHA-256 and then an RIPEMD-160
  BipAddress({
    String? address,
    String? pubkey,
    String? signature,
    String? hash160,
    Script? scriptPubKey,
    Script? scriptSig,
    NetworkType? networkType,
  }) {
    this._networkType = networkType ?? NetworkType.BITCOIN;

    if (scriptSig != null) {
      _decodeScriptSig(scriptSig);
    } else {
      if (pubkey != null) {
        _pubkey = pubkey;
      }
      if (signature != null) {
        _signature = signature;
      }
    }

    if (_pubkey != null) {
      final bytes = _pubkey!.hexToBytes;
      if (!bytes.isPoint) {
        throw ArgumentError("Input has invalid pubkey");
      }
      _h160 = _pubkey!.hexToBytes.ripemd160Hash.hex;
    } else if (hash160 != null) {
      if (!isValidHash160(hash160)) {
        throw Exception("Invalid value for parameter hash160.");
      }
      _h160 = hash160;
    } else if (address != null) {
      if (!isValidAddress(address, type, network: this.networkType))
        throw ArgumentError("Invalid address");

      _h160 = _addressToHash160(address);
    } else if (scriptPubKey != null) {
      _h160 = _scriptToHash160(scriptPubKey);
    } else {
      if (type == AddressType.p2pk) return;
      throw ArgumentError("Not enough data");
    }
  }

  String? _pubkey;
  String? _signature;
  late final String _h160;
  late final NetworkType _networkType;

  String? get pubkey {
    return _pubkey;
  }

  String? get signature {
    return _signature;
  }

  NetworkType get networkType {
    return _networkType;
  }

  String get h160 {
    if (type == AddressType.p2pk) throw UnimplementedError();
    return _h160;
  }

  String _addressToHash160(String address) {
    final decode = bs58check.decode(address);
    return decode.sublist(1).hex;
  }

  String _scriptToHash160(Script s) {
    throw UnimplementedError();
  }

  void _decodeScriptSig(Script s) {
    throw UnimplementedError();
  }

  /// returns the address's string encoding
  @override
  String get address {
    Uint8List tobytes = _h160.hexToBytes;
    switch (type) {
      case AddressType.p2wpkhInP2sh:
      case AddressType.p2wshInP2sh:
      case AddressType.p2pkhInP2sh:
      case AddressType.p2pkInP2sh:
        tobytes = Uint8List.fromList([networkType.p2shPrefix, ...tobytes]);
        break;
      case const (AddressType.p2pkh) || const (AddressType.p2pk):
        tobytes = Uint8List.fromList([networkType.p2pkhPrefix, ...tobytes]);
        break;
      default:
    }
    return bs58check.encode(tobytes);
  }
}

class P2shAddress extends BipAddress {
  P2shAddress({
    super.address,
    super.pubkey,
    super.signature,
    super.hash160,
    super.scriptPubKey,
    super.scriptSig,
    super.networkType,
  }) : type = AddressType.p2pkInP2sh;

  static RegExp get REGEX => RegExp(r'(^|\s)[23][a-km-zA-HJ-NP-Z1-9]{25,34}($|\s)');

  @override
  final AddressType type;

  P2shAddress.fromScript({super.scriptPubKey, this.type = AddressType.p2pkInP2sh})
      : assert(type == AddressType.p2pkInP2sh ||
            type == AddressType.p2pkhInP2sh ||
            type == AddressType.p2wpkhInP2sh ||
            type == AddressType.p2wshInP2sh);

  @override
  Script get scriptPubkey {
    return Script(script: [OP_WORDS.OP_HASH160, _h160, OP_WORDS.OP_EQUAL]);
  }
}

class P2pkhAddress extends BipAddress {
  P2pkhAddress({
    super.address,
    super.pubkey,
    super.signature,
    super.hash160,
    super.scriptPubKey,
    super.scriptSig,
    super.networkType,
  });

  static RegExp get REGEX => RegExp(r'(^|\s)[1mn][a-km-zA-HJ-NP-Z1-9]{25,34}($|\s)');
  static get overheadSizeVB => 10;
  static get inputSizeVB => 148;
  static get outputSizeVB => 34;

  @override
  Script get scriptPubkey {
    return Script(script: [
      OP_WORDS.OP_DUP,
      OP_WORDS.OP_HASH160,
      _h160,
      OP_WORDS.OP_EQUALVERIFY,
      OP_WORDS.OP_CHECKSIG
    ]);
  }

  @override
  AddressType get type => AddressType.p2pkh;

  // https://bitcoin.stackexchange.com/questions/105262/is-a-valid-bitcoin-address-character
  static bool validPubkeyScript(Uint8List data) {
    // A P2PKH output script is composed of the following instructions:
    return data.length == 25 &&
        // OP_DUP (0x76)
        data[0] == OPS['OP_DUP'] &&
        // OP_HASH160 (0xa9)
        data[1] == OPS['OP_HASH160'] &&
        // 0x14 (20 in hexadecimal, indicating a 20 byte push)
        data[2] == 0x14 &&
        // <pubkey hash> (20 bytes)
        // ... data[3] to data[22] ...
        // OP_EQUALVERIFY (0x88)
        data[23] == OPS['OP_EQUALVERIFY'] &&
        // OP_CHECKSIG (0xac)
        data[24] == OPS['OP_CHECKSIG'];
  }

  @override
  String _scriptToHash160(Script s) {
    if (!validPubkeyScript(s.toBytes())) throw new ArgumentError('Output is invalid');
    final h160 = s.script[2];
    return h160;
  }

  static bool validSigScript(List<dynamic>? data) {
    if (data == null || data.isEmpty) throw new ArgumentError('Input is invalid');

    List<String> chunks =
        (data is Uint8List) ? Script.fromRaw(byteData: data).script : (data as List<String>);

    if (chunks.length != 2) throw new ArgumentError('Input is invalid');

    if (!bscript.isCanonicalScriptSignature(chunks[0].fromHex))
      throw new ArgumentError('Input has invalid signature');

    if (!bscript.isCanonicalPubKey(chunks[1].fromHex))
      throw new ArgumentError('Input has invalid pubkey');

    return true;
  }

  @override
  void _decodeScriptSig(Script sigScript) {
    final chunks = sigScript.script;
    if (!validSigScript(sigScript.script)) throw new ArgumentError('Input is invalid');

    _pubkey = chunks[1];
    _signature = chunks[0];
  }

  Script get sigScript {
    return Script(script: [_signature, _pubkey]);
  }
}

// Deprecated but may be useful for library uses, like identifying old P2PK payments, parsing addresses etc
class P2pkAddress extends BipAddress {
  P2pkAddress({required super.pubkey});

  static RegExp get REGEX => RegExp(r'(^|\s)1([A-Za-z0-9]{34})($|\s)');

  late final String publicHex;

  @override
  Script get scriptPubkey {
    return Script(script: [publicHex, OP_WORDS.OP_CHECKSIG]);
  }

  @override
  AddressType get type => AddressType.p2pk;
}
