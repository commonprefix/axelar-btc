use std::{cmp, collections::BTreeMap};

use bitcoin::{
    absolute::LockTime, script, transaction, Address, Amount, ScriptBuf, TapSighash, TxIn, TxOut,
    Weight, Witness,
};
use bitcoin_rs::transaction::TaprootSighash;

use crate::utils::{
    calculate_output_distribution, estimate_taproot_input_vbytes, estimate_taproot_output_vbytes,
    should_update_verifier_set, Utxo, COMMITTEE_SIZE, SIG_SIZE,
};

type Payouts = Vec<(Amount, Address)>;
#[derive(Clone)]
pub struct VerifierSet {
    pub signers: BTreeMap<String, String>,
}

pub struct MultisigProverConfig {
    pub verifier_set_diff_threshold: usize, // threshold for updating the verifier set
    pub min_amount_per_output: Amount,
    pub max_tx_size_vbytes: usize,
}

pub struct MultisigProver {
    pub available_utxos: Vec<Utxo>,
    pub verifier_set: VerifierSet,
    pub config: MultisigProverConfig,
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
        miner_fee: Amount,
        old_script: &ScriptBuf,
        new_script_pubkey: &ScriptBuf,
        new_verifier_set: &VerifierSet,
    ) -> Option<Vec<(transaction::Transaction, Vec<TapSighash>)>> {
        if !should_update_verifier_set(
            new_verifier_set,
            &self.verifier_set,
            self.config.verifier_set_diff_threshold,
        ) {
            return None;
        }

        Some(self.consolidate_utxos(max_output_no, miner_fee, old_script, new_script_pubkey))
    }

    pub fn consume_utxos(
        &mut self,
        payouts: Payouts, // First elements are net payments to the client after extracting our fee
        miner_fee_per_vbyte: Amount, // fee in sats per vbyte
        dust_limit: Amount, // TODO: take into account dust_limit
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
            .map(|(net_payout, receiver)| transaction::TxOut {
                value: *net_payout,
                script_pubkey: receiver.script_pubkey(),
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

    pub fn consolidate_utxos(
        &self,
        max_output_no: usize,
        miner_fee: Amount, // TODO: should probable be fee per vbyte instead of an absolute amount
        script: &ScriptBuf,
        script_pubkey: &ScriptBuf,
    ) -> Vec<(transaction::Transaction, Vec<TapSighash>)> {
        let mut transactions = Vec::new();
        let mut remaining_utxos = self.available_utxos.clone();

        let input_size_vbytes = estimate_taproot_input_vbytes(script, COMMITTEE_SIZE);
        let output_size_vbytes = estimate_taproot_output_vbytes(script_pubkey);

        while !remaining_utxos.is_empty() {
            let mut current_utxos = Vec::new();
            let mut current_tx_size = 0;
            let mut total_input_value = Amount::ZERO;

            for utxo in remaining_utxos.iter() {
                let new_total_input_value = total_input_value + utxo.txout.value;

                let (total_outputs, _, _) = calculate_output_distribution(
                    max_output_no as u64,
                    new_total_input_value - miner_fee, // TODO: make sure that miner_fee is greater than the total value
                    self.config.min_amount_per_output,
                );

                let outputs_size_vbytes = (total_outputs as usize) * output_size_vbytes;

                let new_tx_size = current_tx_size + input_size_vbytes + outputs_size_vbytes;

                if new_tx_size > self.config.max_tx_size_vbytes {
                    break;
                }

                current_utxos.push(utxo.clone());
                current_tx_size = new_tx_size;
                total_input_value += utxo.txout.value;
            }

            if current_utxos.is_empty() {
                break;
            }

            remaining_utxos = remaining_utxos[current_utxos.len()..].to_vec();

            let (total_outputs, amount_per_output, remainder) = calculate_output_distribution(
                max_output_no as u64,
                total_input_value - miner_fee,
                self.config.min_amount_per_output,
            );

            let tx_inputs: Vec<TxIn> = current_utxos
                .iter()
                .map(|utxo| transaction::TxIn {
                    previous_output: utxo.outpoint,
                    script_sig: script::ScriptBuf::new(),
                    sequence: transaction::Sequence::MAX,
                    witness: Witness::default(),
                })
                .collect();

            let mut tx_outputs = Vec::with_capacity(total_outputs as usize);
            let mut amount_left = total_input_value;
            for i in 0..total_outputs {
                let mut output_amount = cmp::min(amount_per_output, amount_left);
                if i == total_outputs - 1 {
                    // Add remainder to the last output
                    output_amount += remainder;
                }

                tx_outputs.push(transaction::TxOut {
                    value: output_amount,
                    script_pubkey: script_pubkey.clone(),
                });

                amount_left -= output_amount;
            }
            let prevouts: Vec<TxOut> = current_utxos
                .iter()
                .map(|utxo| utxo.txout.clone())
                .collect();

            let tx = transaction::Transaction {
                version: transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: tx_inputs,
                output: tx_outputs,
            };

            transactions.push((tx.clone(), tx.taproot_sighashes(prevouts, script)));
        }
        transactions
    }
}
