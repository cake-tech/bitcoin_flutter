import 'dart:typed_data';

extension IntExt on int {
  Uint8List get toLittleEndianBytes {
    var buffer = ByteData(4);
    buffer.setInt32(0, this, Endian.little);
    return buffer.buffer.asUint8List();
  }

  Uint8List get toBigEndianBytes {
    var buffer = ByteData(4);
    buffer.setUint32(0, this, Endian.big);
    return buffer.buffer.asUint8List();
  }
}
