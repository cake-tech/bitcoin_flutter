import 'dart:typed_data';
import 'dart:math';
import 'package:bip32/src/utils/ecurve.dart' as ecc;
import 'package:bip32/src/utils/wif.dart' as wif;
import 'package:bitcoin_flutter/src/models/networks.dart';
import 'package:bitcoin_flutter/src/payments/constants/constants.dart';
import 'ec/ec_public.dart';
import 'ec/ec_encryption.dart' as ec;
import 'crypto.dart' as bcrypto;

class ECPair {
  Uint8List? _d;
  Uint8List? _Q;
  NetworkType network;
  bool compressed;
  ECPair(Uint8List? _d, Uint8List? _Q, {NetworkType? network, bool? compressed})
      : this.network = network ?? bitcoin,
        this.compressed = compressed ?? true {
    this._d = _d;
    this._Q = _Q;
  }
  Uint8List get publicKey {
    if (_Q == null) _Q = ecc.pointFromScalar(_d!, compressed);
    return _Q!;
  }

  Uint8List? get privateKey => _d;
  String toWIF() {
    if (privateKey == null) {
      throw new ArgumentError('Missing private key');
    }
    return wif
        .encode(new wif.WIF(version: network.wif, privateKey: privateKey!, compressed: compressed));
  }

  Uint8List sign(Uint8List hash) {
    return ecc.sign(hash, privateKey!);
  }

  bool verify(Uint8List hash, Uint8List signature) {
    return ecc.verify(hash, publicKey, signature);
  }

  factory ECPair.fromWIF(String w, {NetworkType? network}) {
    wif.WIF decoded = wif.decode(w);
    final version = decoded.version;
    // TODO support multi networks
    NetworkType nw;
    if (network != null) {
      nw = network;
      if (nw.wif != version) throw new ArgumentError('Invalid network version');
    } else {
      if (version == bitcoin.wif) {
        nw = bitcoin;
      } else if (version == testnet.wif) {
        nw = testnet;
      } else {
        throw new ArgumentError('Unknown network version');
      }
    }
    return ECPair.fromPrivateKey(decoded.privateKey, compressed: decoded.compressed, network: nw);
  }
  factory ECPair.fromPublicKey(Uint8List publicKey, {NetworkType? network, bool? compressed}) {
    if (!ecc.isPoint(publicKey)) {
      throw new ArgumentError('Point is not on the curve');
    }
    return new ECPair(null, publicKey, network: network, compressed: compressed);
  }
  factory ECPair.fromPrivateKey(Uint8List privateKey, {NetworkType? network, bool? compressed}) {
    if (privateKey.length != 32)
      throw new ArgumentError('Expected property privateKey of type Buffer(Length: 32)');
    if (!ecc.isPrivate(privateKey)) throw new ArgumentError('Private key not in range [1, n)');
    return new ECPair(privateKey, null, network: network, compressed: compressed);
  }
  factory ECPair.makeRandom({NetworkType? network, bool? compressed, Function? rng}) {
    final rfunc = rng ?? _randomBytes;
    Uint8List d;
//    int beginTime = DateTime.now().millisecondsSinceEpoch;
    do {
      d = rfunc(32);
      if (d.length != 32) throw ArgumentError('Expected Buffer(Length: 32)');
//      if (DateTime.now().millisecondsSinceEpoch - beginTime > 5000) throw ArgumentError('Timeout');
    } while (!ecc.isPrivate(d));
    return ECPair.fromPrivateKey(d, network: network, compressed: compressed);
  }

  /// sign taproot transaction digest and returns the signature.
  Uint8List signTapRoot(Uint8List txDigest,
      {int sighash = TAPROOT_SIGHASH_ALL, List<dynamic> scripts = const [], bool tweak = true}) {
    Uint8List byteKey = Uint8List(0);
    if (tweak) {
      final ECPublic publicKey = ECPublic.fromBytes(_Q!);
      final t = publicKey.calculateTweek(script: scripts);
      byteKey = ec.tweekTapprotPrivate(_d!, t);
    } else {
      byteKey = _d!;
    }
    final randAux = bcrypto.singleHash(Uint8List.fromList([...txDigest, ...byteKey]));
    Uint8List signatur = ec.schnorrSign(txDigest, byteKey, randAux);
    if (sighash != TAPROOT_SIGHASH_ALL) {
      signatur = Uint8List.fromList([...signatur, sighash]);
    }
    return signatur;
  }
}

const int _SIZE_BYTE = 255;
Uint8List _randomBytes(int size) {
  final rng = Random.secure();
  final bytes = Uint8List(size);
  for (var i = 0; i < size; i++) {
    bytes[i] = rng.nextInt(_SIZE_BYTE);
  }
  return bytes;
}
