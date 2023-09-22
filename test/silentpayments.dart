import 'package:bitcoin_flutter/src/payments/silentpayments.dart';
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

  group('Outputs', () {
    test(
      'can create silent payments public keys',
      () {
        final given = [
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('0239a1e5ff6206cd316151b9b34cee4f80bb48ce61adee0a12ce7ff05ea436a1d9', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16', false),
            ],
            [
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('0239a1e5ff6206cd316151b9b34cee4f80bb48ce61adee0a12ce7ff05ea436a1d9', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 3),
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 7),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('03162f2298705b3ddca01ce1d214eedff439df3927582938d08e29e464908db00b', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16', false),
            ],
            [
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 7),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 3),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('02d9ede52f7e1e64e36ccf895ca0250daad96b174987079c903519b17852b21a3f', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('020aafdcdb5893ae813299b16eea75f34ec16653ac39171da04d7c4e6d2e09ab8e', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', true),
              ('fc8716a97a48ba9a05a98ae47b5cd201a25a7fd5d8b73c203c5f7b6b6b3b6ad7', true),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('0215d1dfe4403791509cf47f073be2eb3277decabe90da395e63b1f49a09fe965e', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', true),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', true),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('0215d1dfe4403791509cf47f073be2eb3277decabe90da395e63b1f49a09fe965e', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', true),
              ('8d4751f6e8a3586880fb66c19ae277969bd5aa06f61c4ee2f1e2486efdf666d3', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('032b4ff8e5bc608cbdd12117171e7d265b6882ad597559caf67b5ecfaf15301dd0', 0.1),
            ],
          ),
          (
            [
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', true),
              ('8d4751f6e8a3586880fb66c19ae277969bd5aa06f61c4ee2f1e2486efdf666d3', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
            ],
            [
              ('0275f501f319db549aaa613717bd7af44da566d4d859b67fe436946564fafc47a3', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.2
              ),
            ],
            [
              ('0264f1c7e8992352d18cdbca600b9e1c3a6025050d56a3e1cc833222e4f3b59e18', 0.1),
              ('030a48c6ccc1d516e8244dc0153dc88db45f8f264357667c2057a29ca3c2445d09', 0.2),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.2
              ),
              (
                'sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn',
                0.3
              ),
              (
                'sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn',
                0.4
              ),
            ],
            [
              ('0264f1c7e8992352d18cdbca600b9e1c3a6025050d56a3e1cc833222e4f3b59e18', 0.1),
              ('030a48c6ccc1d516e8244dc0153dc88db45f8f264357667c2057a29ca3c2445d09', 0.2),
              ('02c58e121044b23cba9b4695052229a9fd9e044b579f92864eb886ae7c99b021c9', 0.3),
              ('034b15b75f3f184328c4a2f7c79357481ed06cf3b6f95512d5ed946fdc0b60d62b', 0.4),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqhmem6grvs4nacsu0v5v5mjs934j7qfgkdkj8c95gyuru3tjpulvcwky2dz',
                0.1
              ),
            ],
            [
              ('022cbceeab2a4982841eb7dc34b8b4f19c04bf3bc083ebf984f5664366778eb50f', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqc389f45lq7jyqt8jxq6fkskfukr2tlruf6w8cpcx2krntwe4fr9ykagp3j',
                0.1
              ),
            ],
            [
              ('036b4455de119f51bf4d4a12dea555f14a5dc2c1369af5fba4871c5367264c028d', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq4umqa5feskydh9xadc9jlc22c89tu0apcv72u2vkuwtsrgzf0uesq45zq9',
                0.1
              ),
            ],
            [
              ('03c3473bfcbe5e4d20d0790ae91f1b339bc15b46de64ca068d140118d0e325b849', 0.1),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqah4hxfsjdwyaeel4g8x2npkj7qlvf2692l5760z5ut0ggnlrhdzsy3cvsj',
                0.2
              ),
            ],
            [
              ('0264f1c7e8992352d18cdbca600b9e1c3a6025050d56a3e1cc833222e4f3b59e18', 0.1),
              ('027956317130124c32afd07b3f2432a3e92c1447cf58da95491a307ae3d564535e', 0.2),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqah4hxfsjdwyaeel4g8x2npkj7qlvf2692l5760z5ut0ggnlrhdzsy3cvsj',
                0.1
              ),
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqah4hxfsjdwyaeel4g8x2npkj7qlvf2692l5760z5ut0ggnlrhdzsy3cvsj',
                0.2
              ),
            ],
            [
              ('038890c19f005d6f6add5fef92d37ac6b161b7fdd5c1aef6eed1d32be3f216ac4c', 0.1),
              ('027956317130124c32afd07b3f2432a3e92c1447cf58da95491a307ae3d564535e', 0.2),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqah4hxfsjdwyaeel4g8x2npkj7qlvf2692l5760z5ut0ggnlrhdzsy3cvsj',
                0.2
              ),
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq562yg7htxyg8eq60rl37uul37jy62apnf5ru62uef0eajpdfrnp5cmqndj',
                0.3
              ),
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq562yg7htxyg8eq60rl37uul37jy62apnf5ru62uef0eajpdfrnp5cmqndj',
                0.4
              ),
            ],
            [
              ('0264f1c7e8992352d18cdbca600b9e1c3a6025050d56a3e1cc833222e4f3b59e18', 0.1),
              ('027956317130124c32afd07b3f2432a3e92c1447cf58da95491a307ae3d564535e', 0.2),
              ('031b90a42136fef9ff2ca192abffc7be4536dc83d4e61cf18ae078f7e92b297cce', 0.3),
              ('0287a82600c08a255bc97d172e10816e322967eed6a77c9f37dd926492d7fdc106', 0.4),
            ],
          ),
          (
            [
              ('eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1', false),
              ('0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a', false),
            ],
            [
              ('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
              ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0),
            ],
            [
              (
                'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv',
                0.1
              ),
              (
                'sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqll5497pp2gcr4cmq0v5nv07x8u5jswmf8ap2q0kxmx8628mkqanyu63ck8',
                0.2
              ),
            ],
            [
              ('0264f1c7e8992352d18cdbca600b9e1c3a6025050d56a3e1cc833222e4f3b59e18', 0.1),
              ('020050c52a32566c0dfb517e473c68fedce4bd4543d219348d3bbdceeeb5755e34', 0.2),
            ],
          ),
        ];

        given.forEach((data) {
          final (privateKeys, givenOutpoints, recipients, expected) = data;

          final expectedOutputAddresses = expected.map((x) => x.$1).toList();

          final inputPrivKeys = decodePrivateKeys(privateKeys);

          final outpoints = decodeOutpoints(givenOutpoints);

          final outpointsHash = hashOutpoints(outpoints);

          final silentAddresses = recipients.map((x) => x.$1).toList();

          final aSum = getSumInputPrivKeys(inputPrivKeys);

          final outputs = generateMultipleRecipientPubkeys(aSum, outpointsHash, silentAddresses);

          int i = 0;
          outputs.forEach((recipientSilentAddress, generatedOutput) {
            final expectedAddress = silentAddresses[i];
            expect(recipientSilentAddress, expectedAddress);

            generatedOutput.forEach((output) {
              final expectedPubkey = expectedOutputAddresses[i];
              final generatedPubkey = HEX.encode(output.data);
              expect(generatedPubkey, expectedPubkey);
              i++;
            });
          });
        });
      },
    );
  });
}
