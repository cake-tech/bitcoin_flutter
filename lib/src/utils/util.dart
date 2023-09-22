import 'dart:typed_data';

import 'package:hex/hex.dart';

extension StringExt on String {
  Uint8List get fromHex {
    return Uint8List.fromList(HEX.decode(this));
  }
}

extension ToBytesLittleEndian on int {
  Uint8List toBytesLittleEndian() {
    var buffer = ByteData(4);
    buffer.setInt32(0, this, Endian.little);
    return buffer.buffer.asUint8List();
  }
}
