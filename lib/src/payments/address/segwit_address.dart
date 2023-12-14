import '../../crypto.dart';
import '../../formatting/bytes_num_formatting.dart';

import '../../models/networks.dart';
import 'core.dart';
import '../constants/constants.dart';
import '../script/script.dart';
import '../../utils/string.dart';
import '../../utils/uint8list.dart';
import '../../ec/ec_public.dart';
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
      _program = _addressToHash(address, network: network);
    } else if (script != null) {
      _program = _scriptToHash(script);
    } else if (pubkey != null) {
      _program = hash160(pubkey.fromHex).hex;
    }
  }

  late final String _program;

  String get getProgram => _program;

  final String version;
  late final int segwitNumVersion;

  String _addressToHash(String address, {NetworkType? network}) {
    network ??= bitcoin;
    Segwit? convert;
    try {
      convert = segwit.decode(address, isBech32m: this.version == P2TR_ADDRESS_V1);
    } catch (_) {}
    if (convert == null) {
      throw ArgumentError("Invalid value for parameter address.");
    }

    if (network.bech32 != convert.hrp)
      throw new ArgumentError('Invalid prefix or Network mismatch');

    if (convert.version != segwitNumVersion) {
      throw ArgumentError("Invalid segwit version.");
    }
    return bytesToHex(convert.program);
  }

  /// returns the address's string encoding (Bech32)
  @override
  String toAddress(NetworkType networkType) {
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
  static RegExp get REGEX => RegExp(r'^(bc|tb)1q[ac-hj-np-z02-9]{25,39}$');

  /// Encapsulates a P2WPKH address.
  P2wpkhAddress({super.address, super.program, super.pubkey, super.network})
      : super(version: P2WPKH_ADDRESS_V0);

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
  static RegExp get REGEX =>
      RegExp(r'^(bc)|(tb)1p([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1p[ac-hj-np-z02-9]{8,89}$');

  /// Encapsulates a P2TR (Taproot) address.
  P2trAddress({String? program, super.address, String? pubkey, super.network})
      : super(
            version: P2TR_ADDRESS_V1,
            program: program ?? (pubkey != null ? ECPublic.fromHex(pubkey).toTapPoint() : null));

  /// returns the address's string encoding (Bech32m different from Bech32)
  @override
  String toAddress(NetworkType networkType) {
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
