import 'package:bip32/bip32.dart';
import 'package:bitcoin_flutter/src/templates/silentpaymentaddress.dart';
import 'package:coinlib/coinlib.dart' show loadCoinlib, ECPublicKey;
import 'package:test/test.dart';
import '../lib/src/address.dart' show Address;
import '../lib/src/models/networks.dart' as NETWORKS;
import '../lib/src/utils/util.dart';
import 'package:bip39/bip39.dart' as bip39;

main() async {
  await loadCoinlib();

  group('Address', () {
    group('validateAddress', () {
      group('Silent Payments', () {
        final scanKey = '036a1035a192f8f5fd375556f36ea4abc387361d32c709831ec624a5b73d0b7b9d';
        final spendKey = '028eaf19db65cece905cf2b3eab811148d6fe874089a4a68e5d8b0a1a0904f6bd0';
        final silentAddress =
            'sprt1qqd4pqddpjtu0tlfh24t0xm4y40pcwdsaxtrsnqc7ccj2tdeapdae6q5w4uvakewwe6g9eu4na2upz9yddl58gzy6ff5wtk9s5xsfqnmt6q30zssg';

        test('can encode scan and spend key to silent payment address', () {
          expect(
              SilentPaymentReceiver(
                scanPubkey: ECPublicKey(scanKey.fromHex),
                spendPubkey: ECPublicKey(spendKey.fromHex),
                hrp: 'sprt',
                version: 0,
              ).toString(),
              silentAddress);
        });
        test('can decode scan and spend key from silent payment address', () {
          expect(
              SilentPaymentReceiver.fromString(silentAddress).toString(),
              SilentPaymentReceiver(
                scanPubkey: ECPublicKey(scanKey.fromHex),
                spendPubkey: ECPublicKey(spendKey.fromHex),
                hrp: 'sprt',
                version: 0,
              ).toString());
        });

        test('can derive scan and spend key from master key', () {
          const mnemonic =
              'praise you muffin lion enable neck grocery crumble super myself license ghost';
          final address = SilentPaymentAddress.fromMnemonic(mnemonic);

          final seed = bip39.mnemonicToSeed(mnemonic);
          final root = BIP32.fromSeed(seed);

          expect(address.scanPrivkey.data, root.derivePath("m/352'/0'/0'/1'/0'").privateKey!);
          expect(address.scanPubkey.data, root.derivePath("m/352'/0'/0'/1'/0'").publicKey);

          expect(address.spendPrivkey.data, root.derivePath("m/352'/0'/0'/0'/0'").privateKey!);
          expect(address.spendPubkey.data, root.derivePath("m/352'/0'/0'/0'/0'").publicKey);
        });
      });
      test('base58 addresses and valid network', () {
        expect(
            Address.validateAddress('mhv6wtF2xzEqMNd3TbXx9TjLLo6mp2MUuT', NETWORKS.testnet), true);
        expect(Address.validateAddress('1K6kARGhcX9nJpJeirgcYdGAgUsXD59nHZ'), true);
      });
      test('base58 addresses and invalid network', () {
        expect(
            Address.validateAddress('mhv6wtF2xzEqMNd3TbXx9TjLLo6mp2MUuT', NETWORKS.bitcoin), false);
        expect(
            Address.validateAddress('1K6kARGhcX9nJpJeirgcYdGAgUsXD59nHZ', NETWORKS.testnet), false);
      });
      test('bech32 addresses and valid network', () {
        expect(
            Address.validateAddress('tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya', NETWORKS.testnet),
            true);
        expect(Address.validateAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), true);
        // expect(Address.validateAddress('tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy'), true); TODO
      });
      test('bech32 addresses and invalid network', () {
        expect(Address.validateAddress('tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya'), false);
        expect(
            Address.validateAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', NETWORKS.testnet),
            false);
      });
      test('invalid addresses', () {
        expect(Address.validateAddress('3333333casca'), false);
      });
    });
  });
}
