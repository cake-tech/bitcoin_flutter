import 'dart:typed_data';

import 'package:coinlib/coinlib.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:bitcoin_flutter/src/utils/uint8list.dart';

class Outpoint extends OutPoint {
  Outpoint(Uint8List hash, int n) : super(hash, n);

  String get txid => hash.hex;
  int get index => n;

  Outpoint.fromHex(String txid, int index) : this(txid.fromHex, index);
}
