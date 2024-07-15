use bitcoin::{absolute::LockTime, script, transaction, Amount, ScriptBuf, Witness};
use bitcoincore_rpc::{Client, RpcApi};

use crate::{create_op_return, Utxo};

pub struct User;

impl User {
    // Simulates a deposit transaction from the user. It uses the whole amount available from the given
    // UTXO, minus 600 SATS for fee.
    pub fn peg_in(
        input: Utxo,
        script_pubkey: &ScriptBuf,
        rpc: &Client,
    ) -> transaction::Transaction {
        let tx_in = transaction::TxIn {
            previous_output: input.outpoint,
            script_sig: script::ScriptBuf::new(),
            sequence: transaction::Sequence::MAX,
            witness: Witness::new(),
        };

        let fee = Amount::from_sat(600);
        let amount_per_output =
            input.txout.value.checked_div(2).unwrap() - fee.checked_div(2).unwrap();

        let mut txouts = vec![];
        for _ in 0..2 {
            txouts.push(transaction::TxOut {
                value: amount_per_output,
                script_pubkey: script_pubkey.clone(),
            })
        }

        // GMP data: destination chain, address and payload
        let op_return_out = transaction::TxOut {
            value: Amount::ZERO,
            script_pubkey: create_op_return(),
        };
        txouts.push(op_return_out);

        let unsigned_tx = transaction::Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![tx_in],
            output: txouts,
        };

        let signed_raw_transaction = rpc
            .sign_raw_transaction_with_wallet(&unsigned_tx, None, None)
            .unwrap();
        if !signed_raw_transaction.complete {
            println!("{:#?}", signed_raw_transaction.errors);
            panic!("Transaction couldn't be signed.")
        }
        signed_raw_transaction.transaction().unwrap()
    }
}
