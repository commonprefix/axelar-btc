use core::panic;
use std::{cmp, collections::BTreeMap};

use bitcoin::{
    absolute::LockTime, script, transaction, Address, Amount, ScriptBuf, TapSighash, TxIn, TxOut,
    Witness,
};
use bitcoin_rs::transaction::TaprootSighash;
use chrono::{DateTime, Duration, Utc};

use crate::utils::{
    calculate_output_distribution, estimate_taproot_input_vbytes, estimate_taproot_output_vbytes,
    should_update_verifier_set, Utxo, COMMITTEE_SIZE,
};

type Payouts = Vec<(Amount, Address)>;
#[derive(Clone)]
pub struct VerifierSet {
    pub signers: BTreeMap<String, String>,
}

pub struct MultisigProverConfig {
    pub verifier_set_diff_threshold: usize, // threshold for updating the verifier set
    pub min_amount_per_output: Amount,
    pub max_tx_size_vbytes: u64,
    pub max_output_no: usize,
}

pub struct MultisigProver {
    pub available_utxos: Vec<Utxo>,
    pub last_consolidation_timestamp: i64,
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
            self.consume_utxos(payouts, miner_fee_per_vbyte, Amount::from_sat(10), &script);

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
        &mut self,
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

        Some(self.consolidate_utxos(miner_fee, old_script, new_script_pubkey))
    }

    pub fn consume_utxos(
        &mut self,
        payouts: Payouts,
        miner_fee_per_vbyte: Amount,
        dust_limit: Amount, // TODO: take into account dust_limit
        script: &ScriptBuf,
    ) -> (
        Vec<transaction::TxIn>,
        Vec<transaction::TxOut>,
        Vec<transaction::TxOut>,
        Amount,
    ) {
        let outputs: Vec<TxOut> = payouts
            .iter()
            .map(|(net_payout, receiver)| transaction::TxOut {
                value: *net_payout,
                script_pubkey: receiver.script_pubkey(),
            })
            .collect();

        let total_outputs_size_vbytes: u64 = outputs
            .iter()
            .map(|output| estimate_taproot_output_vbytes(&output.script_pubkey))
            .sum();

        // Calculate the initial target amount needed to cover payouts and miner fees
        // Also account for fees for at least one input
        let total_payouts: Amount = payouts.iter().map(|(payout, _)| *payout).sum();
        let mut target_amount = total_payouts
            + miner_fee_per_vbyte
                * (total_outputs_size_vbytes
                    + estimate_taproot_input_vbytes(script, COMMITTEE_SIZE as u64));

        // Sort UTXOs by value in ascending order
        let mut sorted_utxos = self.available_utxos.clone();
        sorted_utxos.sort_by(|a, b| a.txout.value.cmp(&b.txout.value));

        let mut input_amount = Amount::ZERO;
        let mut selected_utxos = Vec::new();

        // Try to find the smallest UTXO greater than the target amount
        if let Some(utxo) = sorted_utxos
            .iter()
            .find(|utxo| utxo.txout.value > target_amount)
        {
            selected_utxos.push(utxo.clone());
            input_amount += utxo.txout.value;
        } else if let Some(utxo) = sorted_utxos
            // Otherwise, find the largest UTXO smaller than the target amount
            .iter()
            .rev()
            .find(|utxo| utxo.txout.value <= target_amount)
        {
            selected_utxos.push(utxo.clone());
            input_amount += utxo.txout.value;
        } else {
            panic!("Not enough funds to cover the payouts");
        }

        // Fill in the rest with the smallest UTXOs until we reach or exceed the target amount
        for utxo in sorted_utxos.iter() {
            if input_amount >= target_amount {
                break;
            }

            if !selected_utxos.contains(&utxo) {
                selected_utxos.push(utxo.clone());
                input_amount += utxo.txout.value;
            }

            target_amount +=
                miner_fee_per_vbyte * estimate_taproot_input_vbytes(script, COMMITTEE_SIZE as u64);
        }

        if input_amount < target_amount {
            panic!("Not enough funds to cover the payouts");
        }

        let mut inputs = vec![];
        let mut prevouts = vec![];
        for utxo in selected_utxos.iter() {
            let txin = transaction::TxIn {
                previous_output: utxo.outpoint,
                script_sig: script::ScriptBuf::new(),
                sequence: transaction::Sequence::MAX,
                witness: Witness::default(),
            };
            inputs.push(txin);
            prevouts.push(utxo.txout.clone());
        }

        let change = input_amount - target_amount;

        (inputs, prevouts, outputs, change)
    }

    pub fn consolidate_utxos(
        &mut self,
        miner_fee: Amount, // TODO: should probable be fee per vbyte instead of an absolute amount
        script: &ScriptBuf,
        script_pubkey: &ScriptBuf,
    ) -> Vec<(transaction::Transaction, Vec<TapSighash>)> {
        let mut transactions = Vec::new();
        let mut remaining_utxos = self.available_utxos.clone();

        let input_size_vbytes = estimate_taproot_input_vbytes(script, COMMITTEE_SIZE as u64);
        let output_size_vbytes = estimate_taproot_output_vbytes(script_pubkey);

        while !remaining_utxos.is_empty() {
            let mut current_utxos = Vec::new();
            let mut current_tx_size = 0;
            let mut total_input_value = Amount::ZERO;

            for utxo in remaining_utxos.iter() {
                let new_total_input_value = total_input_value + utxo.txout.value;

                let (total_outputs, _, _) = calculate_output_distribution(
                    self.config.max_output_no as u64,
                    new_total_input_value - miner_fee, // TODO: make sure that miner_fee is greater than the total value
                    self.config.min_amount_per_output,
                );

                let outputs_size_vbytes = total_outputs * output_size_vbytes;

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
                self.config.max_output_no as u64,
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

        self.last_consolidation_timestamp = Utc::now().timestamp();

        transactions
    }

    pub fn should_consolidate_utxos(&self) -> bool {
        for utxo in self.available_utxos.iter() {
            if utxo.txout.value < self.config.min_amount_per_output / 2 {
                // TODO: calibrate that
                return true;
            }
        }

        if self.available_utxos.len() > self.config.max_output_no * 2 {
            // TODO: calibrate that
            return true;
        }

        let now = chrono::Utc::now();
        let last_consolidation = DateTime::from_timestamp(self.last_consolidation_timestamp, 0)
            .unwrap()
            .to_utc();

        if now - last_consolidation > Duration::seconds(10) {
            // TODO: calibrate that
            return true;
        }

        return false;
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr, vec};

    use bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut, Txid};
    use bitcoin_hashes::Hash;

    use crate::{
        multisig_prover::{MultisigProver, MultisigProverConfig, VerifierSet},
        utils::{
            estimate_taproot_input_vbytes, estimate_taproot_output_vbytes, Utxo, COMMITTEE_SIZE,
        },
    };

    fn mock_utxo(amount: Amount, id: usize) -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: id as u32,
            },
            txout: TxOut {
                value: amount,
                script_pubkey: ScriptBuf::default(),
            },
        }
    }

    fn mock_available_utxos(amounts: Vec<Amount>) -> Vec<Utxo> {
        let mut utxos = Vec::new();
        for (i, amount) in amounts.iter().enumerate() {
            utxos.push(mock_utxo(*amount, i));
        }
        utxos
    }

    fn mock_multisig_prover(available_utxos: Vec<Utxo>) -> MultisigProver {
        MultisigProver {
            available_utxos,
            last_consolidation_timestamp: 0,
            verifier_set: VerifierSet {
                signers: BTreeMap::new(),
            },
            config: MultisigProverConfig {
                verifier_set_diff_threshold: 1,
                min_amount_per_output: Amount::from_sat(1000),
                max_tx_size_vbytes: 1000,
                max_output_no: 4,
            },
        }
    }

    #[test]
    fn test_consume_utxos_fill_with_larger_utxo() {
        let address = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k")
            .unwrap()
            .assume_checked();
        let available_utxos = mock_available_utxos(vec![
            Amount::from_sat(3000),
            Amount::from_sat(5000),
            Amount::from_sat(10_000),
        ]);
        let mut multisig_prover = mock_multisig_prover(available_utxos.clone());
        let sat_fee_per_vbyte = Amount::from_sat(1);
        let payouts = vec![
            (Amount::from_sat(4000), address.clone()),
            (Amount::from_sat(4000), address.clone()),
        ];

        let (inputs, prevouts, outputs, change) = multisig_prover.consume_utxos(
            payouts.clone(),
            sat_fee_per_vbyte,
            Amount::from_sat(1),
            &ScriptBuf::default(),
        );

        let total_outputs_size_vbytes: u64 = outputs
            .iter()
            .map(|output| estimate_taproot_output_vbytes(&output.script_pubkey))
            .sum();
        let expected_tx_size = inputs.len() as u64
            * estimate_taproot_input_vbytes(&ScriptBuf::default(), COMMITTEE_SIZE as u64)
            + total_outputs_size_vbytes;

        // Change was computed correctly
        assert_eq!(
            change,
            Amount::from_sat(10_000 - 8000) - sat_fee_per_vbyte * expected_tx_size
        );

        // Outputs were computed correctly
        assert_eq!(outputs.len(), payouts.len());
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(
                *output,
                TxOut {
                    value: payouts[i].0,
                    script_pubkey: payouts[i].1.script_pubkey(),
                }
            );
        }

        // Inputs were selected correctly
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].previous_output, available_utxos[2].outpoint);

        // Prevouts were selected correctly
        assert_eq!(prevouts.len(), 1);
        assert_eq!(prevouts[0], available_utxos[2].txout);
    }

    #[test]
    fn test_consume_utxos_fill_with_smaller_utxos() {
        let address = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k")
            .unwrap()
            .assume_checked();
        let available_utxos = mock_available_utxos(vec![
            Amount::from_sat(1000),
            Amount::from_sat(2000),
            Amount::from_sat(3000),
            Amount::from_sat(4000),
            Amount::from_sat(5000),
        ]);
        let mut multisig_prover = mock_multisig_prover(available_utxos.clone());
        let sat_fee_per_vbyte = Amount::from_sat(1);
        let payouts = vec![(Amount::from_sat(5500), address.clone())];

        let (inputs, prevouts, outputs, change) = multisig_prover.consume_utxos(
            payouts.clone(),
            sat_fee_per_vbyte,
            Amount::from_sat(1),
            &ScriptBuf::default(),
        );

        let total_outputs_size_vbytes: u64 = outputs
            .iter()
            .map(|output| estimate_taproot_output_vbytes(&output.script_pubkey))
            .sum();
        let expected_tx_size = inputs.len() as u64
            * estimate_taproot_input_vbytes(&ScriptBuf::default(), COMMITTEE_SIZE as u64)
            + total_outputs_size_vbytes;

        // Change was computed correctly
        assert_eq!(
            change,
            Amount::from_sat(5000 + 1000 + 2000 + 3000 - 5500)
                - sat_fee_per_vbyte * expected_tx_size
        );

        // Outputs were computed correctly
        assert_eq!(outputs.len(), payouts.len());
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(
                *output,
                TxOut {
                    value: payouts[i].0,
                    script_pubkey: payouts[i].1.script_pubkey(),
                }
            );
        }

        // Inputs were selected correctly
        assert_eq!(inputs.len(), 4);
        assert_eq!(inputs[0].previous_output, available_utxos[4].outpoint);
        assert_eq!(inputs[1].previous_output, available_utxos[0].outpoint);
        assert_eq!(inputs[2].previous_output, available_utxos[1].outpoint);
        assert_eq!(inputs[3].previous_output, available_utxos[2].outpoint);

        // Prevouts were selected correctly
        assert_eq!(prevouts.len(), 4);
        assert_eq!(prevouts[0], available_utxos[4].txout);
        assert_eq!(prevouts[1], available_utxos[0].txout);
        assert_eq!(prevouts[2], available_utxos[1].txout);
        assert_eq!(prevouts[3], available_utxos[2].txout);
    }
}
