import 'package:bip32/bip32.dart';
import 'package:bitcoin_flutter/src/templates/silentpaymentaddress.dart';
import 'package:bitcoin_flutter/src/utils/constants/derivation_paths.dart';
import 'package:elliptic/elliptic.dart';
import 'package:test/test.dart';
import '../lib/src/address.dart' show Address;
import 'package:bitcoin_flutter/src/models/networks.dart' as NETWORKS;
import '../lib/src/utils/string.dart';
import 'package:bip39/bip39.dart' as bip39;

main() {
  group('Address', () {
    group('silent payment addresses', () {
      final scanKey = '036a1035a192f8f5fd375556f36ea4abc387361d32c709831ec624a5b73d0b7b9d';
      final spendKey = '028eaf19db65cece905cf2b3eab811148d6fe874089a4a68e5d8b0a1a0904f6bd0';
      final silentAddress =
          'sprt1qqd4pqddpjtu0tlfh24t0xm4y40pcwdsaxtrsnqc7ccj2tdeapdae6q5w4uvakewwe6g9eu4na2upz9yddl58gzy6ff5wtk9s5xsfqnmt6q30zssg';

      final curve = getSecp256k1();

      test('can encode scan and spend key to silent payment address', () {
        expect(
            SilentPaymentAddress(
                    scanPubkey: PublicKey.fromHex(curve, scanKey),
                    spendPubkey: PublicKey.fromHex(curve, spendKey),
                    hrp: 'sprt',
                    version: 0)
                .toString(),
            silentAddress);
      });
      test('can decode scan and spend key from silent payment address', () {
        expect(
            SilentPaymentAddress.fromString(silentAddress).toString(),
            SilentPaymentAddress(
                    scanPubkey: PublicKey.fromHex(curve, scanKey),
                    spendPubkey: PublicKey.fromHex(curve, spendKey),
                    hrp: 'sprt',
                    version: 0)
                .toString());
      });

      test('can derive scan and spend key from master key', () async {
        const mnemonic =
            'praise you muffin lion enable neck grocery crumble super myself license ghost';
        final address = await SilentPaymentReceiver.fromMnemonic(mnemonic);

        final seed = bip39.mnemonicToSeed(mnemonic);
        final root = BIP32.fromSeed(seed);

        expect(
            address.scanPrivkey.toCompressedHex().fromHex, root.derivePath(SCAN_PATH).privateKey!);
        expect(address.scanPubkey.toCompressedHex().fromHex, root.derivePath(SCAN_PATH).publicKey);

        expect(address.spendPrivkey.toCompressedHex().fromHex,
            root.derivePath(SPEND_PATH).privateKey!);
        expect(
            address.spendPubkey.toCompressedHex().fromHex, root.derivePath(SPEND_PATH).publicKey);
      });

      test('can create a labeled silent payment address', () {
        final given = [
          (
            '0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4',
            '025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36',
            '0000000000000000000000000000000000000000000000000000000000000001',
            'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqah4hxfsjdwyaeel4g8x2npkj7qlvf2692l5760z5ut0ggnlrhdzsy3cvsj',
          ),
          (
            '0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4',
            '025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36',
            '0000000000000000000000000000000000000000000000000000000000000539',
            'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq562yg7htxyg8eq60rl37uul37jy62apnf5ru62uef0eajpdfrnp5cmqndj',
          ),
          (
            '03b4cc0b090b6f49a684558852db60ee5eb1c5f74352839c3d18a8fc04ef7354e0',
            '03bc95144daf15336db3456825c70ced0a4462f89aca42c4921ee7ccb2b3a44796',
            '91cb04398a508c9d995ff4a18e5eae24d5e9488309f189120a3fdbb977978c46',
            'sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqll5497pp2gcr4cmq0v5nv07x8u5jswmf8ap2q0kxmx8628mkqanyu63ck8',
          ),
        ];

        given.forEach((data) {
          final (scanKey, spendKey, label, address) = data;
          final result = SilentPaymentAddress.createLabeledSilentPaymentAddress(
              PublicKey.fromHex(curve, scanKey), PublicKey.fromHex(curve, spendKey), label.fromHex);

          expect(result.toString(), address);
        });
      });
    });
    test('base58 addresses and valid network', () {
      expect(Address.validateAddress('mhv6wtF2xzEqMNd3TbXx9TjLLo6mp2MUuT', NETWORKS.testnet), true);
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
    test('bech32m addresses and valid network', () {
      expect(
          Address.validateAddress(
              'tb1pk426x6qvmncj5vzhtp5f2pzhdu4qxsshszswga8ea6sycj9nulmsu7syz0', NETWORKS.testnet),
          true);
      expect(
          Address.validateAddress(
              'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y'),
          true);
    });
    test('bech32m addresses and invalid network', () {
      expect(
          Address.validateAddress('tb1pk426x6qvmncj5vzhtp5f2pzhdu4qxsshszswga8ea6sycj9nulmsu7syz0'),
          false);
      expect(
          Address.validateAddress(
              'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y',
              NETWORKS.testnet),
          false);
    });
    test('invalid addresses', () {
      expect(Address.validateAddress('3333333casca'), false);
    });
  });
}
