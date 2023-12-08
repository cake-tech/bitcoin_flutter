import 'dart:typed_data';

extension BigIntExt on BigInt {
  Uint8List get decode {
    var number = this;
    int needsPaddingByte;
    int rawSize;

    if (number > BigInt.zero) {
      rawSize = (number.bitLength + 7) >> 3;
      needsPaddingByte =
          ((number >> (rawSize - 1) * 8) & BigInt.from(0x80)) == BigInt.from(0x80) ? 1 : 0;

      if (rawSize < 32) {
        needsPaddingByte = 1;
      }
    } else {
      needsPaddingByte = 0;
      rawSize = (number.bitLength + 8) >> 3;
    }

    final size = rawSize < 32 ? rawSize + needsPaddingByte : rawSize;
    var result = Uint8List(size);
    for (int i = 0; i < size; i++) {
      result[size - i - 1] = (number & BigInt.from(0xff)).toInt();
      number = number >> 8;
    }
    return result;
  }
}
