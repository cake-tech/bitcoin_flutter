import 'package:bitcoin_flutter/src/utils/outpoints.dart';
import 'package:bitcoin_flutter/src/utils/keys.dart';
import 'package:coinlib/coinlib.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

main() {
  loadCoinlib();

  group('Utils', () {
    test('can calculate hash of outpoints in tx', () {
      final given = [
        (
          [
            (
              'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16',
              0,
            ),
            (
              'a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d',
              0,
            ),
          ],
          '210fef5d624db17c965c7597e2c6c9f60ef440c831d149c43567c50158557f12',
        ),
        (
          [
            (
              'a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d',
              7,
            ),
            (
              'a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d',
              3,
            ),
          ],
          '1b85dfe15f0d5e1cedd47bdd70c24ecb0e3401c0a2ace659c422916626b66bce',
        ),
        (
          [
            (
              'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16',
              3,
            ),
            (
              'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16',
              7,
            ),
          ],
          'dd7d2a8678cb65b52119af415b578437f5dfc0d9f5bf2daac5e25c21bf0731ce',
        ),
      ];

      given.forEach((data) {
        final (givenOutpoints, expected) = data;
        final outpoints = decodeOutpoints(givenOutpoints);
        final outpointsHash = hashOutpoints(outpoints);
        expect(HEX.encode(outpointsHash), expected);
      });
    });

    test('can calculate sum of private keys', () {
      final given = [
        (
          [
            (
              'eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1',
              false,
            ),
            (
              '93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16',
              false,
            ),
          ],
          '7ed265a6dac7aba8508a32d6d6b84c7f1dbd0a0941dd01088d69e8d556345f86',
        ),
        (
          [
            (
              'eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1',
              true,
            ),
            (
              'fc8716a97a48ba9a05a98ae47b5cd201a25a7fd5d8b73c203c5f7b6b6b3b6ad7',
              true,
            ),
          ],
          'e7638ebfda3ab3849a5707e240a6627671f7f6e609bf172691cf1e9780e51d47',
        ),
        (
          [
            (
              'eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1',
              false,
            ),
            (
              'eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1',
              false,
            ),
          ],
          'd5b8f02cbfe3f1d5295af9fb8a9320e859e9cb07115856486ab1a4e4fb89a621',
        ),
        (
          [
            (
              '0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a',
              true,
            ),
            (
              '8d4751f6e8a3586880fb66c19ae277969bd5aa06f61c4ee2f1e2486efdf666d3',
              false,
            ),
          ],
          '89ce68a062ec130286a4f1a6163f499983814cf61f8aeac76e6f654d98fb9069',
        ),
        (
          [
            (
              'eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1',
              false,
            ),
            (
              '0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a',
              false,
            ),
          ],
          'ee55616ce5a93e508f03f21949ecbe70a2a0b107b6e1df5d98b4e4da4adaca1b',
        ),
      ];

      given.forEach((data) {
        final (keys, expected) = data;
        final silentAddresses = decodePrivateKeys(keys);
        final sum = getSumInputPrivKeys(silentAddresses);
        expect(HEX.encode(sum.data), expected);
      });
    });
  });
}
