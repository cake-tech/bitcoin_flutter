import '../script/script.dart';
import '../../models/networks.dart';

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
        label = 'Legacy (1...)';
        break;
      case AddressType.p2wpkh:
        label = 'SegWit (bc1q...)';
        break;
      case AddressType.p2tr:
        label = 'Taproot (bc1p...)';
        break;
      case AddressType.p2sp:
        label = 'Silent Payments (sp1p...)';
        break;
      default:
        label = 'Mainnet';
        break;
    }
    return label;
  }
}

abstract class BitcoinAddress {
  AddressType get type;
  Script toScriptPubKey();
  String toAddress(NetworkType networkType);
}
