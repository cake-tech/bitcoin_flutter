import '../script/script.dart';
import '../../models/networks.dart';

enum AddressType {
  p2pkh,
  p2wpkh,
  p2pk,
  p2tr,
  p2wsh,
  p2wshInP2sh,
  p2wpkhInP2sh,
  p2pkhInP2sh,
  p2pkInP2sh
}

abstract class BitcoinAddress {
  AddressType get type;
  Script toScriptPubKey();
  String toAddress(NetworkType networkType);
}
