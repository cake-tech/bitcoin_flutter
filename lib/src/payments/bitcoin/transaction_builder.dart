import 'dart:convert';
import 'dart:typed_data';

import 'package:bitcoin_flutter/src/utils/script.dart';
import 'package:bitcoin_flutter/src/utils/uint8list.dart';
import 'package:bitcoin_flutter/src/utils/string.dart';
import 'package:bitcoin_flutter/src/payments/address/core.dart';
import 'package:bitcoin_flutter/src/payments/address/segwit_address.dart';
import 'package:bitcoin_flutter/src/payments/script/script.dart';
import 'package:bitcoin_flutter/src/payments/bitcoin/input.dart';
import 'package:bitcoin_flutter/src/payments/bitcoin/output.dart';
import 'package:bitcoin_flutter/src/payments/bitcoin/witness.dart';
import 'package:bitcoin_flutter/src/payments/bitcoin/transaction.dart';
import 'package:bitcoin_flutter/src/payments/constants/constants.dart';
import 'package:bitcoin_flutter/src/models/networks.dart';
import 'package:bitcoin_flutter/src/ecpair.dart';
import 'package:bitcoin_flutter/src/payments/bitcoin/utxo_details.dart';

typedef BitcoinSignerCallBack = String Function(
    Uint8List trDigest, UtxoWithOwner utxo, String publicKey);

class BitcoinTransactionBuilder {
  final List<BitcoinOutputDetails> outputs;
  final BigInt fee;
  final List<UtxoWithOwner> utxos;
  late final NetworkType network;
  final String? memo;
  final bool enableRBF;
  final bool isFakeTransaction;
  int maximumFeeRate;

  bool _hasSegwit = false;
  bool _hasTaproot = false;

  BitcoinTransactionBuilder({
    required this.outputs,
    required this.fee,
    required this.utxos,
    this.memo = '',
    this.enableRBF = false,
    this.maximumFeeRate = 2500,
    this.isFakeTransaction = false,
    NetworkType? network,
  }) {
    for (final element in utxos) {
      if (element.utxo.isSegwit()) {
        _hasSegwit = true;
      }
      if (element.utxo.isP2tr()) {
        _hasTaproot = true;
      }
    }
  }

  /// HasSegwit checks whether any of the unspent transaction outputs (UTXOs) in the BitcoinTransactionBuilder's
  /// Utxos list are Segregated Witness (SegWit) UTXOs. It iterates through the Utxos list and returns true if it
  /// finds any UTXO with a SegWit script type; otherwise, it returns false.
  bool get hasSegwit => _hasSegwit;

  /// HasTaproot checks whether any of the unspent transaction outputs (UTXOs) in the BitcoinTransactionBuilder's
  /// Utxos list are Pay-to-Taproot (P2TR) UTXOs. It iterates through the Utxos list and returns true if it finds
  /// any UTXO with a Taproot script type; otherwise, it returns false.
  bool get hasTaproot => _hasTaproot;

  /// This method is used to create a dummy transaction,
  /// allowing us to obtain the size of the original transaction
  /// before conducting the actual transaction. This helps us estimate the transaction cost
  static int estimateTransactionSize(
      {required List<UtxoWithOwner> utxos,
      required List<BitcoinAddress> outputs,
      required NetworkType network,
      String? memo,
      bool enableRBF = false}) {
    final sum = utxos.sumOfUtxosValue();

    /// We consider the total amount for the output because,
    /// in all cases, the size of the amount is 8 bytes.
    final outs = outputs.map((e) => BitcoinOutputDetails(address: e, value: sum)).toList();
    final transactionBuilder = BitcoinTransactionBuilder(
      /// Now, we provide the UTXOs we want to spend.
      utxos: utxos,

      /// We select transaction outputs
      outputs: outs,
      /*
			Transaction fee
			Ensure that you have accurately calculated the amounts.
			If the sum of the outputs, including the transaction fee,
			does not match the total amount of UTXOs,
			it will result in an error. Please double-check your calculations.
		*/
      fee: BigInt.from(0),

      /// network, testnet, mainnet
      network: network,

      /// If you like the note write something else and leave it blank
      memo: memo,
      /*
			RBF, or Replace-By-Fee, is a feature in Bitcoin that allows you to increase the fee of an unconfirmed
			transaction that you've broadcasted to the network.
			This feature is useful when you want to speed up a
			transaction that is taking longer than expected to get confirmed due to low transaction fees.
		*/
      enableRBF: true,

      /// We consider the transaction to be fake so that it doesn't check the amounts
      /// and doesn't generate errors when determining the transaction size.
      isFakeTransaction: true,
    );
    ECPair? fakePrivate;
    final transaction = transactionBuilder.buildTransaction((trDigest, utxo, multiSigPublicKey) {
      fakePrivate ??= ECPair.makeRandom();
      if (utxo.utxo.isP2tr()) {
        return fakePrivate!.signTapRoot(trDigest).hex;
      } else {
        return fakePrivate!.sign(trDigest).hex;
      }
    }, []);

    /// Now we need the size of the transaction. If the transaction is a SegWit transaction,
    /// we use the getVSize method; otherwise, we use the getSize method to obtain the transaction size
    final size = transaction.hasSegwit ? transaction.getVSize() : transaction.getSize();

    return size;
  }

  /// It is used to make the appropriate scriptSig
  Script buildInputScriptPubKeys(UtxoWithOwner utxo, bool isTaproot) {
    if (utxo.isMultiSig()) {
      final script = Script.fromRaw(
          hexData: utxo.ownerDetails.multiSigAddress!.scriptDetails, hasSegwit: true);
      switch (utxo.ownerDetails.multiSigAddress!.address.type) {
        case AddressType.p2wshInP2sh:
          if (isTaproot) {
            return utxo.ownerDetails.multiSigAddress!.address.scriptPubkey;
          }
          return script;
        case AddressType.p2wsh:
          if (isTaproot) {
            return utxo.ownerDetails.multiSigAddress!.address.scriptPubkey;
          }
          return script;
        default:
          return Script(script: []);
      }
    }

    final senderPub = utxo.public();
    switch (utxo.utxo.scriptType) {
      case AddressType.p2pk:
        return senderPub.toRedeemScript();
      case AddressType.p2wsh:
        if (isTaproot) {
          return senderPub.toP2wshAddress().scriptPubkey;
        }
        return senderPub.toP2wshScript();
      case AddressType.p2pkh:
        return senderPub.toAddress().scriptPubkey;
      case AddressType.p2wpkh:
        if (isTaproot) {
          return senderPub.toSegwitAddress().scriptPubkey;
        }
        return senderPub.toAddress().scriptPubkey;
      case AddressType.p2tr:
        return senderPub.toTaprootAddress().scriptPubkey;
      case AddressType.p2pkhInP2sh:
        if (isTaproot) {
          return senderPub.toP2pkhInP2sh().scriptPubkey;
        }
        return senderPub.toAddress().scriptPubkey;
      case AddressType.p2wpkhInP2sh:
        if (isTaproot) {
          return senderPub.toP2wpkhInP2sh().scriptPubkey;
        }
        return senderPub.toAddress().scriptPubkey;
      case AddressType.p2wshInP2sh:
        if (isTaproot) {
          return senderPub.toP2wshInP2sh().scriptPubkey;
        }
        return senderPub.toP2wshScript();
      case AddressType.p2pkInP2sh:
        if (isTaproot) {
          return senderPub.toP2pkInP2sh().scriptPubkey;
        }
        return senderPub.toRedeemScript();
      default:
        return Script(script: []);
    }
  }

  /// generateTransactionDigest generates and returns a transaction digest for a given input in the context of a Bitcoin
  /// transaction. The digest is used for signing the transaction input. The function takes into account whether the
  /// associated UTXO is Segregated Witness (SegWit) or Pay-to-Taproot (P2TR), and it computes the appropriate digest
  /// based on these conditions.
  //
  /// Parameters:
  /// - scriptPubKeys: representing the scriptPubKey for the transaction output being spent.
  /// - input: An integer indicating the index of the input being processed within the transaction.
  /// - utox: A UtxoWithOwner instance representing the unspent transaction output (UTXO) associated with the input.
  /// - transaction: A BtcTransaction representing the Bitcoin transaction being constructed.
  /// - taprootAmounts: A List of BigInt containing taproot-specific amounts for P2TR inputs (ignored for non-P2TR inputs).
  /// - tapRootPubKeys: A List of of Script representing taproot public keys for P2TR inputs (ignored for non-P2TR inputs).
  //
  /// Returns:
  /// - Uint8List: representing the transaction digest to be used for signing the input.
  Uint8List generateTransactionDigest(Script scriptPubKeys, int input, UtxoWithOwner utox,
      BtcTransaction transaction, List<BigInt> taprootAmounts, List<Script> tapRootPubKeys) {
    if (utox.utxo.isSegwit()) {
      if (utox.utxo.isP2tr()) {
        return transaction.getTransactionTaprootDigset(
          txIndex: input,
          scriptPubKeys: tapRootPubKeys,
          amounts: taprootAmounts,
        );
      }
      return transaction.getTransactionSegwitDigit(
          txInIndex: input, script: scriptPubKeys, amount: utox.utxo.value);
    }
    return transaction.getTransactionDigest(txInIndex: input, script: scriptPubKeys);
  }

  /// buildP2wshOrP2shScriptSig constructs and returns a script signature (represented as a List of strings)
  /// for a Pay-to-Witness-Script-Hash (P2WSH) or Pay-to-Script-Hash (P2SH) input. The function combines the
  /// signed transaction digest with the script details of the multi-signature address owned by the UTXO owner.
  //
  /// Parameters:
  /// - signedDigest: A List of strings containing the signed transaction digest elements.
  /// - utx: A UtxoWithOwner instance representing the unspent transaction output (UTXO) and its owner details.
  //
  /// Returns:
  /// - List<String>: A List of strings representing the script signature for the P2WSH or P2SH input.
  List<String> buildP2wshOrP2shScriptSig(List<String> signedDigest, UtxoWithOwner utx) {
    /// The constructed script signature consists of the signed digest elements followed by
    /// the script details of the multi-signature address.
    return ['', ...signedDigest, utx.ownerDetails.multiSigAddress!.scriptDetails];
  }

  /// buildP2shSegwitRedeemScriptSig constructs and returns a script signature (represented as a List of strings)
  /// for a Pay-to-Script-Hash (P2SH) Segregated Witness (SegWit) input. The function determines the script type
  /// based on the UTXO and UTXO owner details and creates the appropriate script signature.
  //
  /// Parameters:
  /// - utx0: A UtxoWithOwner instance representing the unspent transaction output (UTXO) and its owner details.
  //
  /// Returns:
  /// - List<string>: A List of strings representing the script signature for the P2SH SegWit input.
  List<String> buildP2shSegwitRedeemScriptSig(UtxoWithOwner utx0) {
    if (utx0.isMultiSig()) {
      switch (utx0.ownerDetails.multiSigAddress!.address.type) {
        case AddressType.p2wshInP2sh:
          final script = Script.fromRaw(
              hexData: utx0.ownerDetails.multiSigAddress!.scriptDetails, hasSegwit: true);
          final p2wsh = P2wshAddress(script: script);
          return [p2wsh.scriptPubkey.toHex()];
        default:
          throw Exception('Does not support this script type');
      }
    }
    final senderPub = utx0.public();
    switch (utx0.utxo.scriptType) {
      case AddressType.p2wshInP2sh:
        final script = senderPub.toP2wshAddress().scriptPubkey;
        return [script.toHex()];
      case AddressType.p2wpkhInP2sh:
        final script = senderPub.toSegwitAddress().scriptPubkey;
        return [script.toHex()];
      default:
        throw Exception('Does not support this script type');
    }
  }

/*
Unlocking Script (scriptSig): The scriptSig is also referred to as
the unlocking script because it provides data and instructions to unlock
a specific output. It contains information and cryptographic signatures
that demonstrate the right to spend the bitcoins associated with the corresponding scriptPubKey output.
*/
  List<String> buildScriptSig(String signedDigest, UtxoWithOwner utx) {
    final senderPub = utx.public();
    if (utx.utxo.isSegwit()) {
      if (utx.utxo.isP2tr()) {
        return [signedDigest];
      }
      switch (utx.utxo.scriptType) {
        case AddressType.p2wshInP2sh:
        case AddressType.p2wsh:
          final script = senderPub.toP2wshScript();
          return ['', signedDigest, script.toHex()];
        default:
          return [signedDigest, senderPub.toHex()];
      }
    } else {
      switch (utx.utxo.scriptType) {
        case AddressType.p2pk:
          return [signedDigest];
        case AddressType.p2pkh:
          return [signedDigest, senderPub.toHex()];
        case AddressType.p2pkhInP2sh:
          final script = senderPub.toAddress().scriptPubkey;
          return [signedDigest, senderPub.toHex(), script.toHex()];
        case AddressType.p2pkInP2sh:
          final script = senderPub.toRedeemScript();
          return [signedDigest, script.toHex()];
        default:
          throw Exception('Cannot send from this type of address ${utx.utxo.scriptType}');
      }
    }
  }

  List<TxInput> buildInputs() {
    final sequence = enableRBF
        ? (Sequence(seqType: TYPE_REPLACE_BY_FEE, value: 0, isTypeBlock: true)).forInputSequence()
        : null;
    final inputs = <TxInput>[];
    for (int i = 0; i < utxos.length; i++) {
      final e = utxos[i];
      inputs.add(TxInput(
          txId: e.utxo.txHash,
          txIndex: e.utxo.vout,
          sequence: i == 0 && enableRBF ? sequence : null));
    }
    return inputs;
  }

  List<TxOutput> buildOutputs() {
    final outs = <TxOutput>[];
    for (final e in outputs) {
      outs.add(TxOutput(amount: e.value, scriptPubKey: buildOutputScriptPubKey(e)));
    }
    return outs;
  }

/*
the scriptPubKey of a UTXO (Unspent Transaction Output) is used as the locking
script that defines the spending conditions for the bitcoins associated
with that UTXO. When creating a Bitcoin transaction, the spending conditions
specified by the scriptPubKey must be satisfied by the corresponding scriptSig
in the transaction input to spend the UTXO.
*/
  Script buildOutputScriptPubKey(BitcoinOutputDetails addr) {
    return addr.address.scriptPubkey;
  }

/*
The primary use case for OP_RETURN is data storage. You can embed various types of
data within the OP_RETURN output, such as text messages, document hashes, or metadata
related to a transaction. This data is permanently recorded on the blockchain and can
be retrieved by anyone who examines the blockchain's history.
*/
  Script opReturn(String message) {
    try {
      message.fromHex;
      return Script(script: ["OP_RETURN", message]);

      /// ignore: empty_catches
    } catch (e) {}
    final toBytes = utf8.encode(message);
    final toHex = Uint8List.fromList(toBytes).hex;
    return Script(script: ["OP_RETURN", toHex]);
  }

  /// Total amount to spend excluding fees
  BigInt sumOutputAmounts() {
    BigInt sum = BigInt.zero;
    for (final e in outputs) {
      sum += e.value;
    }
    return sum;
  }

  BtcTransaction buildTransaction(BitcoinSignerCallBack sign, List<Script> scriptPubKeys) {
    /// build inputs
    final inputs = buildInputs();

    /// build outout
    final outputs = buildOutputs();

    /// check if you set memos or not
    // if (memo != null) {
    //   outputs.add(TxOutput(amount: BigInt.zero, scriptPubKey: opReturn(memo!)));
    // }

    /// create new transaction with inputs and outputs and isSegwit transaction or not
    final transaction = BtcTransaction(
        inputs: inputs, outputs: outputs, hasSegwit: hasSegwit, hasTaproot: hasTaproot);

    /// we define empty witnesses. maybe the transaction is segwit and We need this
    final wintnesses = <TxWitnessInput>[];

    /// when the transaction is taproot and we must use getTaproot tansaction digest
    /// we need all of inputs amounts and owner script pub keys
    List<BigInt> taprootAmounts = [];
    List<Script> taprootScripts = scriptPubKeys;

    if (hasTaproot) {
      taprootAmounts = utxos.map((e) => e.utxo.value).toList();
      if (taprootScripts.isEmpty)
        taprootScripts = utxos.map((e) => buildInputScriptPubKeys(e, true)).toList();
    }

    /// Well, now let's do what we want for each input
    for (int i = 0; i < inputs.length; i++) {
      /// We receive the owner's ScriptPubKey
      final script = buildInputScriptPubKeys(utxos[i], false);

      /// We generate transaction digest for current input
      print(["signatur", script, utxos[i], transaction, taprootAmounts, scriptPubKeys]);
      final digest = generateTransactionDigest(
          script, i, utxos[i], transaction, taprootAmounts, scriptPubKeys);

      /// handle multisig address
      if (utxos[i].isMultiSig()) {
        final multiSigAddress = utxos[i].ownerDetails.multiSigAddress;
        int sumMultiSigWeight = 0;
        final mutlsiSigSignatures = <String>[];
        for (int ownerIndex = 0; ownerIndex < multiSigAddress!.signers.length; ownerIndex++) {
          /// now we need sign the transaction digest
          var sig = sign(digest, utxos[i], multiSigAddress.signers[ownerIndex].publicKey);
          if (!hasTaproot) {
            sig = encodeSignature(sig.fromHex).hex;
          }
          if (sig.isEmpty) continue;
          for (int weight = 0; weight < multiSigAddress.signers[ownerIndex].weight; weight++) {
            if (mutlsiSigSignatures.length >= multiSigAddress.threshold) {
              break;
            }
            mutlsiSigSignatures.add(sig);
          }
          sumMultiSigWeight += multiSigAddress.signers[ownerIndex].weight;
          if (sumMultiSigWeight >= multiSigAddress.threshold) {
            break;
          }
        }
        if (sumMultiSigWeight != multiSigAddress.threshold) {
          throw StateError("some multisig signature does not exist");
        }

        /// ok we signed, now we need unlocking script for this input
        final scriptSig = buildP2wshOrP2shScriptSig(mutlsiSigSignatures, utxos[i]);

        /// Now we need to add it to the transaction
        /// check if current utxo is segwit or not
        wintnesses.add(TxWitnessInput(stack: scriptSig));
        if (utxos[i].utxo.isP2shSegwit()) {
          /*
				check if we need redeemScriptSig or not
				In a Pay-to-Script-Hash (P2SH) Segregated Witness (SegWit) input,
				the redeemScriptSig is needed for historical and compatibility reasons,
				even though the actual script execution has moved to the witness field (the witnessScript).
				This design choice preserves backward compatibility with older Bitcoin clients that do not support SegWit.
			*/
          final p2shSegwitScript = buildP2shSegwitRedeemScriptSig(utxos[i]);
          inputs[i].scriptSig = Script(script: p2shSegwitScript);
        }
        continue;
      }

      /// now we need sign the transaction digest
      var sig = sign(digest, utxos[i], utxos[i].ownerDetails.publicKey!);

      if (!hasTaproot) {
        sig = encodeSignature(sig.fromHex).hex;
      }

      /// ok we signed, now we need unlocking script for this input
      final scriptSig = buildScriptSig(sig, utxos[i]);

      /// Now we need to add it to the transaction
      /// check if current utxo is segwit or not
      if (utxos[i].utxo.isSegwit()) {
        /// ok is segwit and we append to witness list
        wintnesses.add(TxWitnessInput(stack: scriptSig));
        if (utxos[i].utxo.isP2shSegwit()) {
          /*
				check if we need redeemScriptSig or not
				In a Pay-to-Script-Hash (P2SH) Segregated Witness (SegWit) input,
				the redeemScriptSig is needed for historical and compatibility reasons,
				even though the actual script execution has moved to the witness field (the witnessScript).
				This design choice preserves backward compatibility with older Bitcoin clients that do not support SegWit.
			*/
          final p2shSegwitScript = buildP2shSegwitRedeemScriptSig(utxos[i]);
          inputs[i].scriptSig = Script(script: p2shSegwitScript);
        }
      } else {
        /// ok input is not segwit and we use SetScriptSig to set the correct scriptSig
        inputs[i].scriptSig = Script(script: scriptSig);
        /*
			 the concept of an "empty witness" is related to Segregated Witness (SegWit) transactions
			 and the way transaction data is structured. When a transaction input is not associated
			 with a SegWit UTXO, it still needs to be compatible with
			 the SegWit transaction format. This is achieved through the use of an "empty witness."
			*/
        if (hasSegwit) {
          wintnesses.add(TxWitnessInput(stack: []));
        }
      }
    }

    /// ok we now check if the transaction is segwit We add all witnesses to the transaction
    if (hasSegwit) {
      transaction.witnesses.addAll(wintnesses);
    }

    return transaction;
  }
}
