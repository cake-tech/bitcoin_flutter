import 'dart:typed_data';

import 'package:bitcoin_flutter/src/models/networks.dart';
import 'package:bitcoin_flutter/src/payments/address/address.dart';
import 'package:bitcoin_flutter/src/payments/address/segwit_address.dart';

class Address {
  static bool validateAddress(String address, [NetworkType? nw]) {
    try {
      addressToOutputScript(address, nw);
      return true;
    } catch (err) {
      return false;
    }
  }

  static Uint8List addressToOutputScript(String address, [NetworkType? nw]) {
    NetworkType network = nw ?? bitcoin;

    if (P2pkhAddress.REGEX.hasMatch(address)) {
      return P2pkhAddress(address: address, networkType: network).pubkeyScript.toBytes();
    }

    if (P2shAddress.REGEX.hasMatch(address)) {
      return P2shAddress(address: address, networkType: network).pubkeyScript.toBytes();
    }

    if (P2wpkhAddress.REGEX.hasMatch(address)) {
      return P2wpkhAddress(address: address, networkType: network).pubkeyScript.toBytes();
    }

    if (P2trAddress.REGEX.hasMatch(address)) {
      return P2trAddress(address: address, networkType: network).pubkeyScript.toBytes();
    }

    throw new ArgumentError(address + ' has no matching Script');
  }
}
