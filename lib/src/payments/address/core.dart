import 'package:bitcoin_flutter/src/payments/script/script.dart';
import 'package:bitcoin_flutter/src/models/networks.dart';

enum AddressType {
  // deprecated address type
  p2pk,

  p2pkh,
  p2wpkh,
  p2tr,

  // made up for silent payments, doesn't actually exist
  p2sp,

  p2wsh,
  p2wshInP2sh,
  p2wpkhInP2sh,
  p2pkhInP2sh,
  p2pkInP2sh;

  @override
  String toString() {
    String label = '';
    switch (this) {
      case AddressType.p2pkh:
        label = 'Bitcoin Legacy';
        break;
      case AddressType.p2wpkh:
        label = 'Bitcoin SegWit';
        break;
      case AddressType.p2tr:
        label = 'Bitcoin Taproot';
        break;
      case AddressType.p2sp:
        label = 'Bitcoin Silent Payments';
        break;
      default:
        label = 'Mainnet';
        break;
    }
    return label;
  }
}

abstract class BitcoinAddress {
  NetworkType get networkType;
  AddressType get type;
  Script get pubkeyScript;
  String get address;
}
