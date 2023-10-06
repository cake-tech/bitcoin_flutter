import 'dart:typed_data';

import 'package:hex/hex.dart';

extension StringExt on String {
  Uint8List get fromHex {
    return Uint8List.fromList(HEX.decode(this));
  }
}
