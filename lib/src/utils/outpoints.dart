import 'dart:typed_data';

import 'package:coinlib/coinlib.dart';
import 'package:hex/hex.dart';
import 'package:crypto/crypto.dart'; // Import the crypto package for SHA256
import '../utils/util.dart';
import '../utils/uint8list.dart';

List<OutPoint> decodeOutpoints(List<(String, int)> outpoints) {
  return outpoints.map((outpoint) {
    final (txid, vout) = outpoint;
    return OutPoint(Uint8List.fromList(HEX.decode(txid)), vout);
  }).toList();
}

Uint8List hashOutpoints(List<OutPoint> sendingData) {
  final outpoints = <Uint8List>[];

  for (final outpoint in sendingData) {
    final txid = outpoint.hash;
    final vout = outpoint.n;

    final bytes = Uint8List.fromList(txid);
    outpoints.add(concatenateUint8Lists([
      Uint8List.fromList(bytes.reversed.toList()),
      Uint8List.fromList(vout.toBytesLittleEndian())
    ]));
  }

  outpoints.sort((a, b) => a.compare(b));

  final engine = sha256.convert(concatenateUint8Lists(outpoints));

  return Uint8List.fromList(engine.bytes);
}
