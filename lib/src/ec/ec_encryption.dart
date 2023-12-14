import 'dart:typed_data';

import 'package:bitcoin_flutter/src/utils/bigint.dart';
import 'package:bitcoin_flutter/src/utils/uint8list.dart';
import '../formatting/bytes_num_formatting.dart';
import "package:pointycastle/ecc/curves/secp256k1.dart" show ECCurve_secp256k1;
import 'package:pointycastle/ecc/api.dart' show ECPoint;
import '../crypto.dart';

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
  final aa = a.bigint;
  final bb = b.bigint;
  if (aa == bb) return 0;
  if (aa > bb) return 1;
  return -1;
}

bool isPoint(Uint8List p) {
  // Check if the input list has a length of at least 33 bytes, which is the minimum length required for a compressed representation of a point on the curve
  if (p.length < 33) {
    return false;
  }

  // Extract the first byte of the input list, which represents the type of the point
  var t = p[0];

  // Extract the next 32 bytes, which represent the X coordinate of the point
  var x = p.sublist(1, 33);

  // Check if the X coordinate is equal to zero or infinity, which are invalid values for a point on the curve
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

  // Check if the point is a compressed representation of a point on the curve. If it is, return true.
  if ((t == 0x02 || t == 0x03) && p.length == 33) {
    return true;
  }

  // Extract the next 32 bytes, which represent the Y coordinate of the point
  var y = p.sublist(33);

  // Check if the Y coordinate is equal to zero or infinity, which are invalid values for a point on the curve
  if (_compare(y, _zero32) == 0) {
    return false;
  }
  if (_compare(y, _ecP) == 1) {
    return false;
  }

  // Check if the point is an uncompressed representation of a point on the curve. If it is, return true
  if (t == 0x04 && p.length == 65) {
    return true;
  }

  // If the point is not a valid point on the curve, return false
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
  final r = padUint8ListTo32(x.decode);
  final s = padUint8ListTo32(y.decode);
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
  final r = padUint8ListTo32(x.decode);
  final s = padUint8ListTo32(y.decode);
  return Uint8List.fromList([...r, ...s]);
}

Uint8List xorBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    throw ArgumentError("Input lists must have the same length");
  }

  Uint8List result = Uint8List(a.length);

  for (int i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }

  return result;
}

Uint8List schnorrSign(Uint8List msg, Uint8List secret, Uint8List aux) {
  if (msg.length != 32) {
    throw ArgumentError("The message must be a 32-byte array.");
  }
  final d0 = decodeBigInt(secret);
  if (!(BigInt.one <= d0 && d0 <= n - BigInt.one)) {
    throw ArgumentError("The secret key must be an integer in the range 1..n-1.");
  }
  if (aux.length != 32) {
    throw ArgumentError("aux_rand must be 32 bytes instead of ${aux.length}");
  }
  ECPoint P = (G * d0) as ECPoint;
  BigInt d = d0;
  if (P.y!.toBigInteger()!.isOdd) {
    d = n - d;
  }
  final t = xorBytes(d.decode, taggedHash(aux, "BIP0340/aux"));
  final kHash = taggedHash(
      Uint8List.fromList([...t, ...P.x!.toBigInteger()!.decode, ...msg]), "BIP0340/nonce");
  final k0 = decodeBigInt(kHash) % n;
  if (k0 == BigInt.zero) {
    throw const FormatException('Failure. This happens only with negligible probability.');
  }
  final R = (G * k0) as ECPoint;
  BigInt k = k0;
  if (R.y!.toBigInteger()!.isOdd) {
    k = n - k;
  }
  final eHash = taggedHash(
      Uint8List.fromList([...R.x!.toBigInteger()!.decode, ...P.x!.toBigInteger()!.decode, ...msg]),
      "BIP0340/challenge");

  final e = decodeBigInt(eHash) % n;
  final eKey = (k + e * d) % n;
  final sig = Uint8List.fromList([...R.x!.toBigInteger()!.decode, ...eKey.decode]);
  final verify = verifySchnorr(msg, P.x!.toBigInteger()!.decode, sig);
  if (!verify) {
    throw const FormatException('The created signature does not pass verification.');
  }
  return sig;
}

bool verifySchnorr(Uint8List message, Uint8List publicKey, Uint8List signatur) {
  if (message.length != 32) {
    throw ArgumentError("The message must be a 32-byte array.");
  }
  if (publicKey.length != 32) {
    throw ArgumentError("The public key must be a 32-byte array.");
  }
  if (signatur.length != 64) {
    throw ArgumentError("The signature must be a 64-byte array.");
  }
  final P = liftX(decodeBigInt(publicKey));
  final r = decodeBigInt(signatur.sublist(0, 32));
  final s = decodeBigInt(signatur.sublist(32, 64));
  if (P == null || r >= prime || s >= n) {
    return false;
  }
  final eHash = taggedHash(
      Uint8List.fromList([...signatur.sublist(0, 32), ...publicKey, ...message]),
      "BIP0340/challenge");
  final e = decodeBigInt(eHash) % n;

  final sp = (G * s) as ECPoint;

  final eP = (P * (n - e)) as ECPoint;

  final R = (sp + eP) as ECPoint;
  if (R.y!.toBigInteger()!.isOdd || R.x!.toBigInteger()! != r) {
    return false;
  }
  return true;
}

ECPoint? liftX(BigInt x) {
  if (x >= prime) {
    return null;
  }
  final ySq = (_modPow(x, BigInt.from(3), prime) + BigInt.from(7)) % prime;
  final y = _modPow(ySq, (prime + BigInt.one) ~/ BigInt.from(4), prime);
  if (_modPow(y, BigInt.two, prime) != ySq) return null;
  BigInt result = (y & BigInt.one) == BigInt.zero ? y : prime - y;
  return secp256k1.curve.createPoint(x, result);
}

BigInt _modPow(BigInt base, BigInt exponent, BigInt modulus) {
  if (exponent == BigInt.zero) {
    return BigInt.one;
  }

  BigInt result = BigInt.one;
  base %= modulus;

  while (exponent > BigInt.zero) {
    if ((exponent & BigInt.one) == BigInt.one) {
      result = (result * base) % modulus;
    }
    exponent = exponent ~/ BigInt.two;
    base = (base * base) % modulus;
  }

  return result;
}

Uint8List pubKeyGeneration(Uint8List secret) {
  final d0 = decodeBigInt(secret);
  if (!(BigInt.one <= d0 && d0 <= n - BigInt.one)) {
    throw ArgumentError("The secret key must be an integer in the range 1..n-1.");
  }
  ECPoint qq = (G * d0) as ECPoint;
  Uint8List toBytes = qq.getEncoded(false);
  if (toBytes[0] == 0x04) {
    toBytes = toBytes.sublist(1, toBytes.length);
  }
  return toBytes;
}

BigInt _negatePrivateKey(Uint8List secret) {
  final bytes = pubKeyGeneration(secret);
  final toBigInt = decodeBigInt(bytes.sublist(32));
  BigInt negatedKey = decodeBigInt(secret);
  if (toBigInt.isOdd) {
    final keyExpend = decodeBigInt(secret);
    negatedKey = n - keyExpend;
  }
  return negatedKey;
}

Uint8List tweekTapprotPrivate(Uint8List secret, BigInt tweek) {
  final bytes = pubKeyGeneration(secret);
  final toBigInt = decodeBigInt(bytes.sublist(32));
  BigInt negatedKey = decodeBigInt(secret);
  if (toBigInt.isOdd) {
    negatedKey = _negatePrivateKey(secret);
  }
  final tw = (negatedKey + tweek) % n;
  return tw.decode;
}
