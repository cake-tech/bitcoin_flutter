import 'dart:typed_data';

import 'package:hex/hex.dart';

extension StringExt on String {
  Uint8List get fromHex {
    return Uint8List.fromList(HEX.decode(this));
  }

  String get strip0x {
    if (this.startsWith('0x')) return this.substring(2);
    return this;
  }

  Uint8List get hexToBytes {
    return this.strip0x.fromHex;
  }
}
