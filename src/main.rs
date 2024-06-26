use axelar_btc::{
    create_multisig_script, create_op_return, create_unspendable_internal_key, handover_input_size,
    init_wallet, test_and_submit,
};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, Message, PublicKey};
use bitcoin::sighash::SighashCache;
use bitcoin::sighash::{Prevouts, ScriptPath};
use bitcoin::{OutPoint, TapSighash, TapSighashType, TxOut};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::collections::HashMap;
use std::{cmp, env, ops::Div, path::PathBuf};

use bitcoin::{
    amount::Amount,
    bip32::Xpriv,
    blockdata::{locktime::absolute::LockTime, script, transaction, witness::Witness},
    taproot::{LeafVersion, Signature, TaprootBuilder},
    Network, ScriptBuf, XOnlyPublicKey,
};
use reqwest;

const WALLET: &str = "wallets/default";
const COOKIE: &str = ".cookie";
const COMMITTEE_SIZE: usize = 75;
// TODO: use real weights
const WEIGHTS: [i64; COMMITTEE_SIZE] = [
    1, 2, 4, 5, 4, 7, 5, 5, 4, 2, 10, 5, 4, 3, 3, 2, 2, 4, 3, 2, 4, 5, 6, 6, 4, 3, 2, 2, 5, 4, 2,
    7, 3, 4, 4, 4, 2, 7, 3, 2, 5, 4, 4, 4, 3, 5, 4, 5, 5, 4, 8, 4, 3, 5, 6, 4, 4, 6, 6, 5, 3, 5, 6,
    6, 8, 7, 4, 5, 7, 6, 8, 9, 11, 12, 7,
];
const NETWORK: Network = Network::Regtest;
const PEG_IN_OUTPUT_SIZE: usize = 43; // As reported by `peg_in.output[0].size()`. TODO: double-check that this is always right

#[derive(Clone)]
struct Utxo {
    outpoint: OutPoint,
    txout: TxOut,
}

struct User;

struct Validator {
    key: Xpriv,
}

struct MultisigProver {
    available_utxos: Vec<Utxo>,
}

impl User {
    // Simulates a deposit transaction from the user. It uses the whole amount available from the given
    // UTXO, minus 600 SATS for fee.
    fn peg_in(input: Utxo, script_pubkey: &ScriptBuf, rpc: &Client) -> transaction::Transaction {
        let tx_in = transaction::TxIn {
            previous_output: input.outpoint,
            script_sig: script::ScriptBuf::new(),
            sequence: transaction::Sequence::MAX,
            witness: Witness::new(),
        };

        let tx_out = transaction::TxOut {
            value: input.txout.value - Amount::from_sat(600),
            script_pubkey: script_pubkey.clone(),
        };

        // GMP data: destination chain, address and payload
        let op_return_out = transaction::TxOut {
            value: Amount::ZERO,
            script_pubkey: create_op_return(),
        };

        let unsigned_tx = transaction::Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![tx_in],
            output: vec![tx_out, op_return_out],
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

impl MultisigProver {
    // Upon request for unwrapping BTC, the MultisigProver creates a peg_out transaction
    // releasing BTC from the multisig back to a recipient. This transaction will be passed
    // around the validators for signing.
    // The MultisigProver will use all the provided UTXOs for the peg_out transaction. Those
    // UTXOs might have more BTC than required for the withdrawal, so there is also a 'change'
    // output sending the extra BTC back to the multisig.
    fn create_peg_out_tx(
        &self,
        inputs: Vec<Utxo>,
        fee: Amount,
        withdrawal_amount: Amount, // net payout, not including fee for bridge
        receiver_pubkey: &PublicKey,
        script: &ScriptBuf,
        script_pubkey: &ScriptBuf,
    ) -> (transaction::Transaction, TapSighash) {
        let tx_ins = inputs
            .iter()
            .map(|utxo| transaction::TxIn {
                previous_output: utxo.outpoint,
                script_sig: script::ScriptBuf::new(),
                sequence: transaction::Sequence::MAX,
                witness: Witness::default(),
            })
            .collect::<Vec<transaction::TxIn>>();

        // Create outputs for user and change
        let total_input_amount = inputs.iter().map(|utxo| utxo.txout.value).sum::<Amount>();
        let change_amount = total_input_amount - withdrawal_amount - fee;

        let recipient_out = transaction::TxOut {
            value: withdrawal_amount,
            script_pubkey: ScriptBuf::new_p2pk(&(*receiver_pubkey).into()),
        };

        let change_out = transaction::TxOut {
            value: change_amount,
            script_pubkey: script_pubkey.clone(),
        };

        let unsigned_peg_out_tx = transaction::Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_ins,
            output: vec![recipient_out, change_out],
        };

        // Create sighash of peg out transaction to pass it around the validators for signing
        let mut cloned_tx = unsigned_peg_out_tx.clone();
        let mut sighash_cache = SighashCache::new(&mut cloned_tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[inputs[0].txout.clone()]),
                ScriptPath::with_defaults(&script),
                TapSighashType::Default,
            )
            .unwrap();

        (unsigned_peg_out_tx, sighash)
    }

    fn create_handover_tx(
        &self,
        old_outputs: &Vec<Utxo>,
        max_output_no: usize,
        max_tx_size: usize,
        present_committee_count: usize,
        missing_committee_keys: usize,
        new_script_pubkey: &script::ScriptBuf,
    ) -> Vec<transaction::Transaction> {
        let fan_in = cmp::max(1, old_outputs.len() / max_output_no);

        // Assume that all inputs & outputs have the same size
        // This assumption might be wrong for inputs if the number of validator sigs varies
        let input_size = handover_input_size(present_committee_count, missing_committee_keys);
        let max_outputs_per_tx = max_tx_size / (fan_in * input_size + PEG_IN_OUTPUT_SIZE);

        let mut handover_txs = vec![];
        // TODO: maybe use `iter::iterator::array_chunks()` when stabilized to avoid `collect()`ing
        // (https://doc.rust-lang.org/stable/std/iter/trait.Iterator.html#method.array_chunks)
        let old_outputs_chunked_per_new_output: Vec<_> = old_outputs.chunks(fan_in).collect();
        let old_outputs_chunked_per_tx =
            old_outputs_chunked_per_new_output.chunks(max_outputs_per_tx);
        for old_outputs_chunks_for_tx in old_outputs_chunked_per_tx {
            let mut new_tx_inputs = vec![];
            let mut new_tx_outputs = vec![];
            for old_outputs_chunk in old_outputs_chunks_for_tx {
                let mut in_value = Amount::ZERO;
                for utxo in *old_outputs_chunk {
                    in_value += utxo.txout.value;
                    new_tx_inputs.push(transaction::TxIn {
                        previous_output: utxo.outpoint,
                        script_sig: script::ScriptBuf::new(),
                        sequence: transaction::Sequence::MAX,
                        witness: Witness::default(),
                    });
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

            handover_txs.push(tx);
        }

        handover_txs
    }

    // We don't keep track of which txs have been finalized on-chain and which haven't. TODO: maybe add this
    fn consume_utxos(
        &mut self,
        payouts: Vec<(Amount, PublicKey)>, // First elements are net payments to the client after extracting our fee
        miner_fee: Amount,                 // fee in sats per vbyte
        dust_limit: Amount,
    ) -> (Vec<transaction::TxIn>, Amount) {
        let input_value = payouts
            .iter()
            .fold(Amount::ZERO, |acc, (payout, _)| acc + *payout);

        let new_outputs = payouts
            .iter()
            .map(|(net_payout, pk)| transaction::TxOut {
                value: *net_payout,
                script_pubkey: ScriptBuf::new_p2pk(&Into::<bitcoin::PublicKey>::into(*pk)),
            })
            .collect();

        let mut peg_out_tx = transaction::Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: new_outputs,
        };

        // greedily add utxos until the required input_value and fees are reached
        // TODO: choose utxos more intelligently: reduce number of inputs/hit the exact input_value
        let mut collected_input_value = Amount::ZERO;
        let mut goal_value = input_value + miner_fee * peg_out_tx.vsize().try_into().unwrap();
        let mut inputs = vec![];
        while collected_input_value < goal_value {
            let utxo = self.available_utxos.pop().expect(
                // TODO: return Result if failing to peg_out is possible
                &format!(
                    "FATAL: all utxos are not enough to match input_value + fees = {goal_value}"
                ),
            );
            collected_input_value += utxo.txout.value;
            inputs.push(transaction::TxIn {
                previous_output: utxo.outpoint,
                script_sig: script::ScriptBuf::new(),
                sequence: transaction::Sequence::MAX,
                witness: Witness::default(),
            });
            // TODO: update the goal based on the new size
            // goal_value = input_value + miner_fee * peg_out_tx.vsize().try_into().unwrap()
        }

        (inputs, collected_input_value - goal_value)
    }

    fn finalize_tx_witness(
        &self,
        mut tx: transaction::Transaction,
        committee_signatures: &Vec<Option<Signature>>,
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

        // add signatures in the correct order, fill in missing signatures with an empty vector
        for signature in committee_signatures.iter().rev() {
            if let Some(signature) = signature {
                tx.input[0].witness.push(signature.to_vec());
            } else {
                tx.input[0].witness.push(&[]);
            }
        }

        tx.input[0].witness.push(script.to_bytes());
        tx.input[0].witness.push(control_block.serialize());

        tx
    }
}

impl Validator {
    fn new(seed: usize) -> Self {
        Validator {
            key: Xpriv::new_master(NETWORK, &[seed.try_into().unwrap()]).unwrap(),
        }
    }

    fn public_key(&self, secp: &Secp256k1<All>) -> XOnlyPublicKey {
        self.key.to_keypair(&secp).x_only_public_key().0
    }

    // The validators blindly trust the signature hash that they need to sign,
    // and provide their Schnorr signatures on it.
    fn sign_sighash(&self, sighash: &TapSighash, secp: &Secp256k1<All>) -> Signature {
        let msg = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();

        Signature {
            signature: secp.sign_schnorr(&msg, &self.key.to_keypair(&secp)),
            sighash_type: TapSighashType::Default,
        }
    }
}

fn main() {
    let client = reqwest::blocking::Client::new();
    let bitcoin_validators = client
        .post("https://api.axelarscan.io/validator/getChainMaintainers")
        .json(&HashMap::from([("chain", "avalanche")])) // TODO: change `avalanche` to `bitcoin`
        .send()
        .expect("Validators needed")
        .text()
        .expect("Validators needed");
    let all_validators =
        reqwest::blocking::get("https://api.axelarscan.io/validator/getValidators")
            .expect("Validators needed")
            .text()
            .expect("Validators needed");
    println!("{bitcoin_validators:?}");
    todo!();
    let weights = [1,2,3];

    let threshold = weights.iter().sum::<i64>() * Div::<i64>::div(2, 3);
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run <bitcoin_directory>");
        std::process::exit(1);
    }
    let bitcoin_dir = args[1].to_owned() + "/regtest/";

    // Initialize RPC
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::CookieFile(PathBuf::from(&(bitcoin_dir.to_owned() + COOKIE))),
    )
    .unwrap();
    let (address, coinbase_tx, coinbase_vout) = init_wallet(&bitcoin_dir, &rpc, NETWORK, WALLET);

    // Create validators
    let mut validators = vec![];
    for i in 0..COMMITTEE_SIZE {
        validators.push(Validator::new(i));
    }

    // Store the public keys & weights of the validators
    let secp = Secp256k1::new();
    let mut validators_pks_weights = vec![];
    for i in 0..validators.len() {
        validators_pks_weights.push((validators[i].public_key(&secp), weights[i]));
    }

    // Create the multisig bitcoin script and an internal unspendable key
    let internal_key = create_unspendable_internal_key();
    let (script, script_pubkey) =
        create_multisig_script(&validators_pks_weights, internal_key.clone(), threshold, &secp);

    // User: creates a deposit transaction
    let user_utxo = Utxo {
        outpoint: OutPoint {
            txid: coinbase_tx.compute_txid(),
            vout: coinbase_vout,
        },
        txout: coinbase_tx.output[0].clone(),
    };
    let peg_in = User::peg_in(user_utxo, &script_pubkey, &rpc);

    // Create key for recipient of withdrawal
    let receiver_key = Xpriv::new_master(NETWORK, &[0]).unwrap();
    let receiver_pubkey = receiver_key.to_keypair(&secp).public_key();

    // MultisigProver: Creates an unsigned withdrawal transaction
    let multisig_prover = MultisigProver {
        available_utxos: vec![],
    };
    let multisig_utxo = Utxo {
        outpoint: OutPoint {
            txid: peg_in.compute_txid(),
            vout: 0,
        },
        txout: peg_in.output[0].clone(),
    };
    let (unsigned_peg_out, sighash) = multisig_prover.create_peg_out_tx(
        vec![multisig_utxo.clone()],
        Amount::from_sat(5000),
        multisig_utxo.txout.value / 2,
        &receiver_pubkey,
        &script,
        &script_pubkey,
    );

    // Get signatures for the withdrawal from each member of the committee
    let mut committee_signatures = vec![];
    for validator in validators {
        // Missing signatures should be represented with None. Order matters.
        committee_signatures.push(Some(validator.sign_sighash(&sighash, &secp)));
    }

    // MultisigProver: Collect signatures, fill in missing signatures, add control block and finalize witness
    let peg_out = multisig_prover.finalize_tx_witness(
        unsigned_peg_out,
        &committee_signatures,
        &script,
        &internal_key,
        &secp,
    );

    let outputs: Vec<Utxo> = vec![];
    let _ = multisig_prover.create_handover_tx(&outputs, 5, 100000, COMMITTEE_SIZE, 0, &script_pubkey);

    // Test peg in and peg out transactions for mempool acceptance and submit them
    test_and_submit(&rpc, [peg_in, peg_out], address);
}
