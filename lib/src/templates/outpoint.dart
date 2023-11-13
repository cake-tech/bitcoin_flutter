import 'dart:typed_data';

import 'package:bitcoin_flutter/bitcoin_flutter.dart';

class Outpoint {
  Outpoint({required this.txid, required this.index});

  String txid;
  int index;

  factory Outpoint.fromBytes(Uint8List txid, int index) {
    return Outpoint(txid: txid.hex, index: index);
  }

  String toString() {
    return 'Outpoint{txid: $txid, index: $index}';
  }
}
