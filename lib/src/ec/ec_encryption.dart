import 'dart:typed_data';

import '../formatting/bytes_num_formatting.dart';
import "package:pointycastle/ecc/curves/secp256k1.dart" show ECCurve_secp256k1;
import 'package:pointycastle/ecc/api.dart' show ECPoint;

final prime =
    BigInt.parse("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", radix: 16);

final _zero32 = Uint8List(32);
final _ecP = hexToBytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
final secp256k1 = ECCurve_secp256k1();
final n = secp256k1.n;
final G = secp256k1.G;

ECPoint? _decodeFrom(Uint8List P) {
  return secp256k1.curve.decodePoint(P);
}

int _compare(Uint8List a, Uint8List b) {
  BigInt aa = decodeBigInt(a);
  BigInt bb = decodeBigInt(b);
  if (aa == bb) return 0;
  if (aa > bb) return 1;
  return -1;
}

bool isPoint(Uint8List p) {
  if (p.length < 33) {
    return false;
  }
  var t = p[0];
  var x = p.sublist(1, 33);

  if (_compare(x, _zero32) == 0) {
    return false;
  }
  if (_compare(x, _ecP) == 1) {
    return false;
  }
  try {
    _decodeFrom(p);
  } catch (err) {
    return false;
  }
  if ((t == 0x02 || t == 0x03) && p.length == 33) {
    return true;
  }
  var y = p.sublist(33);
  if (_compare(y, _zero32) == 0) {
    return false;
  }
  if (_compare(y, _ecP) == 1) {
    return false;
  }
  if (t == 0x04 && p.length == 65) {
    return true;
  }
  return false;
}

bool _isPointCompressed(Uint8List p) {
  return p[0] != 0x04;
}

Uint8List reEncodedFromForm(Uint8List p, bool compressed) {
  final decode = _decodeFrom(p);
  if (decode == null) {
    throw ArgumentError("Bad point");
  }
  final encode = decode.getEncoded(compressed);
  if (!_isPointCompressed(encode)) {
    return encode.sublist(1, encode.length);
  }

  return encode;
}

Uint8List taprootPoint(Uint8List pub) {
  BigInt x = decodeBigInt(pub.sublist(0, 32));
  BigInt y = decodeBigInt(pub.sublist(32, pub.length));
  if (y.isOdd) {
    y = prime - y;
  }

  var Q = secp256k1.curve.createPoint(x, y);

  if (Q.y!.toBigInteger()!.isOdd) {
    y = prime - Q.y!.toBigInteger()!;
    Q = secp256k1.curve.createPoint(Q.x!.toBigInteger()!, y);
  }
  x = Q.x!.toBigInteger()!;
  y = Q.y!.toBigInteger()!;
  final r = padUint8ListTo32(encodeBigInt(x));
  final s = padUint8ListTo32(encodeBigInt(y));
  return Uint8List.fromList([...r, ...s]);
}

Uint8List tweakTaprootPoint(Uint8List pub, Uint8List tweak) {
  BigInt x = decodeBigInt(pub.sublist(0, 32));
  BigInt y = decodeBigInt(pub.sublist(32, pub.length));
  if (y.isOdd) {
    y = prime - y;
  }
  final tw = decodeBigInt(tweak);

  final c = secp256k1.curve.createPoint(x, y);
  ECPoint qq = (G * tw) as ECPoint;
  ECPoint Q = (c + qq) as ECPoint;

  if (Q.y!.toBigInteger()!.isOdd) {
    y = prime - Q.y!.toBigInteger()!;
    Q = secp256k1.curve.createPoint(Q.x!.toBigInteger()!, y);
  }
  x = Q.x!.toBigInteger()!;
  y = Q.y!.toBigInteger()!;
  final r = padUint8ListTo32(encodeBigInt(x));
  final s = padUint8ListTo32(encodeBigInt(y));
  return Uint8List.fromList([...r, ...s]);
}
