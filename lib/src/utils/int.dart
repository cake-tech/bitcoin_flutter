import 'dart:typed_data';

extension ToBytesLittleEndian on int {
  Uint8List get toBytesLittleEndian {
    var buffer = ByteData(4);
    buffer.setInt32(0, this, Endian.little);
    return buffer.buffer.asUint8List();
  }
}
