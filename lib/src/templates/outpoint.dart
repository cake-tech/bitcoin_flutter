import 'dart:typed_data';

import 'package:bitcoin_flutter/bitcoin_flutter.dart';

class Outpoint {
  Outpoint({required this.txid, required this.index, this.value});

  String txid;
  int index;
  int? value;

  factory Outpoint.fromBytes(Uint8List txid, int index, {int? value}) {
    return Outpoint(txid: txid.hex, index: index, value: value);
  }

  String toString() {
    return 'Outpoint{txid: $txid, index: $index, value: $value}';
  }
}
