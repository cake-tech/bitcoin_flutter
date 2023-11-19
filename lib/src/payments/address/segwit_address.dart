import '../../crypto.dart';
import '../../formatting/bytes_num_formatting.dart';

import '../../models/networks.dart';
import 'core.dart';
import '../constants/constants.dart';
import '../script/script.dart';
import 'package:bech32/bech32.dart';

abstract class SegwitAddress implements BitcoinAddress {
  /// Represents a Bitcoin segwit address
  ///
  /// [program] for segwit v0 this is the hash string representation of either the address;
  /// it can be either a public key hash (P2WPKH) or the hash of the script (P2WSH)
  /// for segwit v1 (aka taproot) this is the public key
  SegwitAddress(
      {String? address,
      String? program,
      Script? script,
      String? pubkey,
      NetworkType? network,
      this.version = P2WPKH_ADDRESS_V0}) {
    if (version == P2WPKH_ADDRESS_V0 || version == P2WSH_ADDRESS_V0) {
      segwitNumVersion = 0;
    } else if (version == P2TR_ADDRESS_V1) {
      segwitNumVersion = 1;
    } else {
      throw ArgumentError('A valid segwit version is required.');
    }
    if (program != null) {
      _program = program;
    } else if (address != null) {
      _program = _addressToHash(address);
    } else if (script != null) {
      _program = _scriptToHash(script);
    }
  }

  late final String _program;

  String get getProgram => _program;

  final String version;
  late final int segwitNumVersion;

  String _addressToHash(String address) {
    Segwit? convert;
    try {
      convert = segwit.decode(address);
    } catch (_) {}
    if (convert == null) {
      throw ArgumentError("Invalid value for parameter address.");
    }
    final version = convert.version;
    if (version != segwitNumVersion) {
      throw ArgumentError("Invalid segwit version.");
    }
    return bytesToHex(convert.program);
  }

  /// returns the address's string encoding (Bech32)
  @override
  String toAddress(NetworkInfo networkType) {
    final bytes = hexToBytes(_program);
    String? sw;
    try {
      sw = segwit.encode(Segwit(networkType.bech32, segwitNumVersion, bytes));
    } catch (_) {}
    if (sw == null) {
      throw ArgumentError("invalid address");
    }

    return sw;
  }

  String _scriptToHash(Script script) {
    final toBytes = script.toBytes();
    final toHash = singleHash(toBytes);
    return bytesToHex(toHash);
  }
}

class P2wpkhAddress extends SegwitAddress {
  /// Encapsulates a P2WPKH address.
  P2wpkhAddress({super.address, super.program, super.version = P2WPKH_ADDRESS_V0});

  /// returns the scriptPubKey of a P2WPKH witness script
  @override
  Script toScriptPubKey() {
    return Script(script: ['OP_0', _program]);
  }

  /// returns the type of address
  @override
  AddressType get type => AddressType.p2wpkh;
}

class P2trAddress extends SegwitAddress {
  /// Encapsulates a P2TR (Taproot) address.
  P2trAddress({
    super.program,
    super.address,
    String? pubkey,
    NetworkType? network,
  }) : super(version: P2TR_ADDRESS_V1, pubkey: pubkey, network: network);

  /// returns the address's string encoding (Bech32m different from Bech32)
  @override
  String toAddress(NetworkInfo networkType) {
    final bytes = hexToBytes(_program);
    String? sw;
    try {
      sw = segwit.encode(Segwit(networkType.bech32, segwitNumVersion, bytes), isBech32m: true);
    } catch (_) {}
    if (sw == null) {
      throw ArgumentError("invalid address");
    }

    return sw;
  }

  /// returns the scriptPubKey of a P2TR witness script
  @override
  Script toScriptPubKey() {
    return Script(script: ['OP_1', _program]);
  }

  /// returns the type of address
  @override
  AddressType get type => AddressType.p2tr;
}

class P2wshAddress extends SegwitAddress {
  /// Encapsulates a P2WSH address.
  P2wshAddress({super.script, super.address}) : super(version: P2WSH_ADDRESS_V0);

  /// Returns the scriptPubKey of a P2WPKH witness script
  @override
  Script toScriptPubKey() {
    return Script(script: ['OP_0', _program]);
  }

  /// Returns the type of address
  @override
  AddressType get type => AddressType.p2wsh;
}