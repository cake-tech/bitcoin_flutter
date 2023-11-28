import 'dart:typed_data';

import 'models/networks.dart';
import 'payments/address/address.dart';
import 'payments/address/segwit_address.dart';

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
      return P2pkhAddress(address: address, network: network).toScriptPubKey().toBytes();
    }

    if (P2shAddress.REGEX.hasMatch(address)) {
      return P2shAddress(address: address, network: network).toScriptPubKey().toBytes();
    }

    if (P2wpkhAddress.REGEX.hasMatch(address)) {
      return P2wpkhAddress(address: address, network: network).toScriptPubKey().toBytes();
    }

    if (P2trAddress.REGEX.hasMatch(address)) {
      return P2trAddress(address: address, network: network).toScriptPubKey().toBytes();
    }

    throw new ArgumentError(address + ' has no matching Script');
  }
}
