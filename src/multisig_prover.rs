use std::cmp;

use bitcoin::{
    absolute::LockTime,
    key::Secp256k1,
    script,
    secp256k1::{All, PublicKey},
    taproot::{LeafVersion, Signature, TaprootBuilder},
    transaction, Amount, ScriptBuf, TapSighash, Weight, Witness, XOnlyPublicKey,
};
use bitcoin_rs::transaction::TaprootSighash;

use crate::{handover_input_size, Utxo, SIG_SIZE};

const PEG_IN_OUTPUT_SIZE: usize = 43; // As reported by `peg_in.output[0].size()`. TODO: double-check that this is always right
const COMMITTEE_SIZE: usize = 75; // TODO: replace

type Payouts = Vec<(Amount, PublicKey)>;

pub struct MultisigProver {
    pub available_utxos: Vec<Utxo>,
}

impl MultisigProver {
    // Upon request for unwrapping BTC, the MultisigProver creates a peg_out transaction
    // releasing BTC from the multisig back to a recipient. This transaction will be passed
    // around the validators for signing.
    // The MultisigProver will use all the provided UTXOs for the peg_out transaction. Those
    // UTXOs might have more BTC than required for the withdrawal, so there is also a 'change'
    // output sending the extra BTC back to the multisig.
    pub fn create_peg_out_tx(
        &mut self,
        miner_fee_per_vbyte: Amount,
        payouts: Payouts,
        script: &ScriptBuf,
        script_pubkey: &ScriptBuf,
    ) -> (transaction::Transaction, Vec<TapSighash>) {
        // TODO: should take into account the maximum tx size as well and split the withdrawals to multiple
        // transctions, like the handover does.

        let (inputs, prevouts, mut outputs, change_amount) =
            self.consume_utxos(payouts, miner_fee_per_vbyte, Amount::from_sat(10));

        let change_output = transaction::TxOut {
            value: change_amount,
            script_pubkey: script_pubkey.clone(),
        };
        outputs.push(change_output);

        let unsigned_peg_out_tx = transaction::Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs.clone(),
            output: outputs,
        };

        // Create sighash of peg out transaction to pass it around the validators for signing
        let sighashes = unsigned_peg_out_tx.taproot_sighashes(prevouts.clone(), script);

        (unsigned_peg_out_tx, sighashes)
    }

    pub fn create_handover_tx(
        &self,
        max_output_no: usize,
        max_tx_size: usize,
        miner_fee: Amount,
        dust_limit: Amount,
        old_script: &ScriptBuf,
        new_script_pubkey: &ScriptBuf,
    ) -> Vec<(transaction::Transaction, Vec<TapSighash>)> {
        // TODO: Maybe we should ceil the old_outputs.len() / max_output_no division to make
        // sure that we always get exactly max_output_no outputs. Consider the case of
        // old_outsputs.len() = 3, max_output_no = 2
        let fan_in = cmp::max(1, self.available_utxos.len() / max_output_no);

        // Assume that all inputs & outputs have the same size
        // This assumption might be wrong for inputs if the number of validator sigs varies
        // TODO: For now, assume that all the validators will sign the handover. An optimization would be
        // to calculate the maximum number of validators that could be required in order to
        // achieve quorum, by summing the stakes of the smallest validators, and use that
        // to calculate the input size.
        let input_size = handover_input_size(COMMITTEE_SIZE);
        let max_outputs_per_tx = max_tx_size / (fan_in * input_size + PEG_IN_OUTPUT_SIZE);

        let mut handover_txs = vec![];
        let mut fee_reducted = false;
        // TODO: maybe use `iter::iterator::array_chunks()` when stabilized to avoid `collect()`ing
        // (https://doc.rust-lang.org/stable/std/iter/trait.Iterator.html#method.array_chunks)
        let old_outputs_chunked_per_new_output: Vec<_> =
            self.available_utxos.chunks(fan_in).collect();
        let old_outputs_chunked_per_tx =
            old_outputs_chunked_per_new_output.chunks(max_outputs_per_tx);
        for old_outputs_chunks_for_tx in old_outputs_chunked_per_tx.clone() {
            let mut new_tx_inputs = vec![];
            let mut new_tx_outputs = vec![];
            let mut prevouts = vec![];
            for old_outputs_chunk in old_outputs_chunks_for_tx {
                let mut in_value = Amount::ZERO;
                for utxo in *old_outputs_chunk {
                    in_value += utxo.txout.value;
                    new_tx_inputs.push(transaction::TxIn {
                        previous_output: utxo.outpoint,
                        script_sig: script::ScriptBuf::new(),
                        sequence: transaction::Sequence::MAX,
                        witness: Witness::default(), // TODO: need signatures here
                    });
                    prevouts.push(utxo.txout.clone().clone());
                }

                // TODO: split the fee among the UTXOs
                if in_value > miner_fee + dust_limit && !fee_reducted {
                    in_value = in_value - miner_fee;
                    fee_reducted = true;
                }

                new_tx_outputs.push(transaction::TxOut {
                    value: in_value,
                    script_pubkey: new_script_pubkey.clone(),
                });
            }

            let tx = transaction::Transaction {
                version: transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: new_tx_inputs,
                output: new_tx_outputs,
            };

            handover_txs.push((tx, prevouts));
        }

        if !fee_reducted {
            // TODO: split the fee among the UTXOs
            panic!("All available UTXOs are less than the fee.")
        }

        handover_txs
            .iter()
            .map(|(tx, prevouts)| {
                (
                    tx.clone(),
                    tx.taproot_sighashes(prevouts.clone(), old_script),
                )
            })
            .collect()
    }

    pub fn consume_utxos(
        &mut self,
        payouts: Payouts, // First elements are net payments to the client after extracting our fee
        miner_fee_per_vbyte: Amount, // fee in sats per vbyte
        dust_limit: Amount,
    ) -> (
        Vec<transaction::TxIn>,
        Vec<transaction::TxOut>,
        Vec<transaction::TxOut>,
        Amount,
    ) {
        let input_value = payouts
            .iter()
            .fold(Amount::ZERO, |acc, (payout, _)| acc + *payout);

        let outputs = payouts
            .iter()
            .map(|(net_payout, pk)| transaction::TxOut {
                value: *net_payout,
                script_pubkey: ScriptBuf::new_p2pk(&Into::<bitcoin::PublicKey>::into(*pk)), // TODO: use p2pkh
            })
            .collect();

        // greedily add utxos until the required input_value and fees are reached
        // TODO: choose utxos more intelligently: reduce number of inputs/hit the exact input_value
        let mut collected_input_value = Amount::ZERO;
        let mut goal_value = input_value;
        let mut inputs = vec![];
        let mut prevouts = vec![];
        while collected_input_value < goal_value {
            let utxo = self.available_utxos.pop().expect(
                // TODO: return Result if failing to peg_out is possible
                &format!(
                    "FATAL: all utxos are not enough to match input_value + fees = {goal_value}"
                ),
            );
            collected_input_value += utxo.txout.value;
            let txin = transaction::TxIn {
                previous_output: utxo.outpoint,
                script_sig: script::ScriptBuf::new(),
                sequence: transaction::Sequence::MAX,
                witness: Witness::default(),
            };
            goal_value += miner_fee_per_vbyte
                * (txin.segwit_weight() + Weight::from_wu_usize(SIG_SIZE)).to_vbytes_ceil();
            inputs.push(txin);
            prevouts.push(utxo.txout);
        }

        let change = collected_input_value - goal_value;

        (inputs, prevouts, outputs, change)
    }

    pub fn finalize_tx_witness(
        &self,
        mut tx: transaction::Transaction,
        committee_signatures: &Vec<Vec<Option<Signature>>>,
        script: &ScriptBuf,
        internal_key: &XOnlyPublicKey,
        secp: &Secp256k1<All>,
    ) -> transaction::Transaction {
        let peg_in_taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&secp, internal_key.clone())
            .unwrap();

        let control_block = peg_in_taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap();

        assert_eq!(tx.input.len(), committee_signatures.len());
        for (input_index, input) in tx.input.iter_mut().enumerate() {
            // add signatures in the correct order, fill in missing signatures with an empty vector
            for signature in committee_signatures[input_index].iter().rev() {
                if let Some(signature) = signature {
                    input.witness.push(signature.to_vec());
                } else {
                    input.witness.push(&[]);
                }
            }

            input.witness.push(script.to_bytes());
            input.witness.push(control_block.serialize());
        }

        tx
    }
}
