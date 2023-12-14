import 'dart:typed_data';
import 'package:bitcoin_flutter/src/crypto.dart';
import 'package:bitcoin_flutter/src/formatting/bytes_num_formatting.dart';
import 'package:bitcoin_flutter/src/ec/ec_encryption.dart';
import 'package:bitcoin_flutter/src/utils/bigint.dart';
import 'package:pointycastle/ecc/api.dart' show ECPoint;

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
