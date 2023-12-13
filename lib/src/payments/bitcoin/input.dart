import 'dart:typed_data';

import 'package:bitcoin_flutter/src/payments/script/script.dart';
import 'package:bitcoin_flutter/src/payments/constants/constants.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:bitcoin_flutter/src/utils/check_types.dart';
import 'package:bitcoin_flutter/src/formatting/bytes_num_formatting.dart';

/// A transaction input requires a transaction id of a UTXO and the index of that UTXO.
///
/// [txId] the transaction id as a hex string
/// [txIndex] the index of the UTXO that we want to spend
/// [scriptSig] the script that satisfies the locking conditions
/// [sequence] the input sequence (for timelocks, RBF, etc.)
class TxInput {
  TxInput({required this.txId, required this.txIndex, Script? scriptSig, Uint8List? sequence})
      : sequence = sequence ?? Uint8List.fromList(DEFAULT_TX_SEQUENCE),
        scriptSig = scriptSig ?? Script(script: []) {
    if (!isHash256bit(txId.fromHex)) throw new ArgumentError('Invalid input hash');
    if (!isUint(txIndex, 32)) throw new ArgumentError('Invalid input index');
  }

  final String txId;
  final int txIndex;
  Script scriptSig;
  Uint8List sequence;

  TxInput copy() {
    return TxInput(txId: txId, txIndex: txIndex, scriptSig: scriptSig, sequence: sequence);
  }

  @override
  String toString() {
    return 'TxInput{txId: $txId, txIndex: $txIndex, scriptSig: $scriptSig, sequence: $sequence}';
  }

  /// serializes TxInput to bytes
  Uint8List toBytes() {
    final txidBytes = Uint16List.fromList(txId.fromHex.reversed.toList());

    final txoutBytes = Uint8List(4);
    ByteData.view(txoutBytes.buffer).setUint32(0, txIndex, Endian.little);

    final scriptSigBytes = scriptSig.toBytes();

    final scriptSigLengthVarint = encodeVarint(scriptSigBytes.length);
    final data = Uint8List.fromList([
      ...txidBytes,
      ...txoutBytes,
      ...scriptSigLengthVarint,
      ...scriptSigBytes,
      ...sequence,
    ]);
    return data;
  }

  static (TxInput, int) fromRaw({required String raw, int cursor = 0, bool hasSegwit = false}) {
    final txInputRaw = hexToBytes(raw);
    Uint8List inpHash =
        Uint8List.fromList(txInputRaw.sublist(cursor, cursor + 32).reversed.toList());
    if (inpHash.isEmpty) {
      throw ArgumentError("Input transaction hash not found. Probably malformed raw transaction");
    }
    Uint8List outputN =
        Uint8List.fromList(txInputRaw.sublist(cursor + 32, cursor + 36).reversed.toList());
    cursor += 36;
    final vi = viToInt(txInputRaw.sublist(cursor, cursor + 9));
    cursor += vi.$2;
    Uint8List unlockingScript = txInputRaw.sublist(cursor, cursor + vi.$1);
    cursor += vi.$1;
    Uint8List sequenceNumberData = txInputRaw.sublist(cursor, cursor + 4);
    cursor += 4;
    return (
      TxInput(
        txId: bytesToHex(inpHash),
        txIndex: int.parse(bytesToHex(outputN), radix: 16),
        scriptSig: Script.fromRaw(hexData: bytesToHex(unlockingScript), hasSegwit: hasSegwit),
        sequence: sequenceNumberData,
      ),
      cursor
    );
  }
}

/// Used to provide the sequence to transaction inputs and to scripts.
///
/// [value] The value of the block height or the 512 seconds increments
/// [seqType] Specifies the type of sequence (TYPE_RELATIVE_TIMELOCK | TYPE_ABSOLUTE_TIMELOCK | TYPE_REPLACE_BY_FEE
/// [isTypeBlock] If type is TYPE_RELATIVE_TIMELOCK then this specifies its type (block height or 512 secs increments)
class Sequence {
  Sequence({required this.seqType, required this.value, this.isTypeBlock = true}) {
    if (seqType == TYPE_RELATIVE_TIMELOCK && (value < 1 || value > 0xffff)) {
      throw ArgumentError('Sequence should be between 1 and 65535');
    }
  }
  final int seqType;
  final int value;
  final bool isTypeBlock;

  /// Serializes the relative sequence as required in a transaction
  Uint8List forInputSequence() {
    if (seqType == TYPE_ABSOLUTE_TIMELOCK) {
      return Uint8List.fromList(ABSOLUTE_TIMELOCK_SEQUENCE);
    }

    if (seqType == TYPE_REPLACE_BY_FEE) {
      return Uint8List.fromList(REPLACE_BY_FEE_SEQUENCE);
    }
    if (seqType == TYPE_RELATIVE_TIMELOCK) {
      int seq = 0;
      if (!isTypeBlock) {
        seq |= 1 << 22;
      }
      seq |= value;
      return Uint8List.fromList([
        seq & 0xFF,
        (seq >> 8) & 0xFF,
        (seq >> 16) & 0xFF,
        (seq >> 24) & 0xFF,
      ]);
    }

    throw ArgumentError("Invalid seqType");
  }

  /// Returns the appropriate integer for a script; e.g. for relative timelocks
  int forScript() {
    if (seqType == TYPE_REPLACE_BY_FEE) {
      throw const FormatException("RBF is not to be included in a script.");
    }
    int scriptIntiger = value;
    if (seqType == TYPE_RELATIVE_TIMELOCK && !isTypeBlock) {
      scriptIntiger |= 1 << 22;
    }
    return scriptIntiger;
  }
}
