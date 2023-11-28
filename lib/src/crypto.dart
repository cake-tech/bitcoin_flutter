import 'dart:typed_data';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/api.dart' show KeyParameter;
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:crypto/crypto.dart' show sha256, Digest;

Uint8List hash160(Uint8List buffer) {
  Uint8List _tmp = new SHA256Digest().process(buffer);
  return new RIPEMD160Digest().process(_tmp);
}

Uint8List hmacSHA512(Uint8List key, Uint8List data) {
  final _tmp = new HMac(new SHA512Digest(), 128)..init(new KeyParameter(key));
  return _tmp.process(data);
}

Uint8List hash256(Uint8List buffer) {
  Uint8List _tmp = new SHA256Digest().process(buffer);
  return new SHA256Digest().process(_tmp);
}

/// Function: doubleHash
/// Description: Computes a double SHA-256 hash of the input data.
/// Input: Uint8List buffer - The data to be hashed.
/// Output: Uint8List - The resulting double SHA-256 hash.
/// Note: Double hashing is a common cryptographic technique used to enhance data security.
Uint8List doubleHash(Uint8List buffer) {
  Digest tmp = sha256.convert(buffer);
  return Uint8List.fromList(sha256.convert(tmp.bytes).bytes);
}

/// Function: singleHash
/// Description: Computes a single SHA-256 hash of the input data.
/// Input: Uint8List buffer - The data to be hashed.
/// Output: Uint8List - The resulting single SHA-256 hash.
/// Note: This function calculates a single SHA-256 hash of the input data.
Uint8List singleHash(Uint8List buffer) {
  /// Compute a single SHA-256 hash of the input data.
  return SHA256Digest().process(buffer);
}

/// Function: taggedHash
/// Description: Computes a tagged hash of the input data with a provided tag.
/// Input:
///   - Uint8List data - The data to be hashed.
///   - String tag - A unique tag to differentiate the hash.
/// Output: Uint8List - The resulting tagged hash.
/// Note: This function combines the provided tag with the input data to create a unique
/// hash by applying a double SHA-256 hash.
Uint8List taggedHash(Uint8List data, String tag) {
  /// Calculate the hash of the tag as Uint8List.
  final tagDigest = singleHash(Uint8List.fromList(tag.codeUnits));

  /// Concatenate the tag hash with itself and the input data.
  final concat = Uint8List.fromList([...tagDigest, ...tagDigest, ...data]);

  /// Compute a double SHA-256 hash of the concatenated data.
  return singleHash(concat);
}
