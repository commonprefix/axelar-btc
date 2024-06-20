use axelar_btc::{
    create_multisig_script, create_op_return, create_unspendable_internal_key, init_wallet,
    test_and_submit,
};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, Message, PublicKey};
use bitcoin::sighash::SighashCache;
use bitcoin::sighash::{Prevouts, ScriptPath};
use bitcoin::{TapSighash, TapSighashType, TxOut, Txid};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::collections::HashMap;
use std::{env, path::PathBuf};

use bitcoin::{
    amount::Amount,
    bip32::Xpriv,
    blockdata::{locktime::absolute::LockTime, script, transaction, witness::Witness},
    taproot::{LeafVersion, Signature, TaprootBuilder},
    Network, ScriptBuf, XOnlyPublicKey,
};

const WALLET: &str = "wallets/default";
const COOKIE: &str = ".cookie";
const COMMITTEE_SIZE: usize = 2;
const NETWORK: Network = Network::Regtest;

struct UTXO {
    txid: Txid,
    txout: TxOut,
    vout: u32,
}

struct User {}

struct Validator {
    key: Xpriv,
}

struct MultisigProver {}

impl User {
    fn peg_in(input: UTXO, script_pubkey: &ScriptBuf, rpc: &Client) -> transaction::Transaction {
        let tx_in = transaction::TxIn {
            previous_output: transaction::OutPoint {
                txid: input.txid,
                vout: u32::try_from(input.vout).unwrap(),
            },
            script_sig: script::ScriptBuf::new(),
            sequence: transaction::Sequence::MAX,
            witness: Witness::new(),
        };

        let tx_out = transaction::TxOut {
            value: input.txout.value - Amount::from_sat(600),
            script_pubkey: script_pubkey.clone(),
        };

        let op_return_out = transaction::TxOut {
            value: Amount::ZERO,
            script_pubkey: create_op_return(),
        };

        let unsigned_tx = transaction::Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![tx_in],
            output: vec![tx_out.clone(), op_return_out],
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
    fn create_peg_out_tx(
        inputs: Vec<UTXO>,
        fee: Amount,
        receiver_pubkey: &PublicKey,
        script: &ScriptBuf,
    ) -> (transaction::Transaction, TapSighash) {
        // Build peg-out tx that spends peg-in tx
        // TODO: iterate over the inputs
        let peg_out_tx_in = transaction::TxIn {
            previous_output: transaction::OutPoint {
                txid: inputs[0].txid,
                vout: inputs[0].vout,
            },
            script_sig: script::ScriptBuf::new(),
            sequence: transaction::Sequence::MAX,
            witness: Witness::default(),
        };

        let p2pk = ScriptBuf::new_p2pk(&(*receiver_pubkey).into());

        let unsigned_peg_out_tx = transaction::Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![peg_out_tx_in],
            output: vec![transaction::TxOut {
                value: inputs[0].txout.value - fee,
                script_pubkey: p2pk,
            }],
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

        return (unsigned_peg_out_tx, sighash);
    }

    fn finalize_tx_witness(
        mut tx: transaction::Transaction,
        committee_signatures: &HashMap<usize, Signature>,
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
        for i in 0..COMMITTEE_SIZE {
            let signature_option = committee_signatures.get(&(COMMITTEE_SIZE - i - 1));
            if let Some(signature) = signature_option {
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

    fn sign_sighash(&self, sighash: &TapSighash, secp: &Secp256k1<All>) -> Signature {
        let msg = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();

        Signature {
            signature: secp.sign_schnorr(&msg, &self.key.to_keypair(&secp)),
            sighash_type: TapSighashType::Default,
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run <bitcoin_directory>");
        std::process::exit(1);
    }
    let bitcoin_dir = args[1].to_owned() + "/regtest/";

    // Initialize RPC
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::CookieFile(PathBuf::from(&(bitcoin_dir.to_owned() + COOKIE))), // TODO: don't hardcode this
    )
    .unwrap();
    let (address, coinbase_tx, coinbase_vout) = init_wallet(&bitcoin_dir, &rpc, NETWORK, WALLET);

    // Create validators
    let mut validators = vec![];
    for i in 0..COMMITTEE_SIZE {
        validators.push(Validator::new(i));
    }

    // Store the public keys of the validators
    let secp = Secp256k1::new();
    let mut validators_pks = vec![];
    for i in 0..validators.len() {
        validators_pks.push(validators[i].public_key(&secp));
    }

    // Create the multisig bitcoin script and an internal unspendable key
    let internal_key = create_unspendable_internal_key();
    let (script, script_pubkey) =
        create_multisig_script(&validators_pks, internal_key.clone(), &secp);

    // User: creates a deposit transaction
    let user_utxo = UTXO {
        txid: coinbase_tx.compute_txid(),
        vout: coinbase_vout,
        txout: coinbase_tx.output[0].clone(),
    };
    let peg_in = User::peg_in(user_utxo, &script_pubkey, &rpc);

    // Create key for recipient of withdrawal
    let receiver_key = Xpriv::new_master(NETWORK, &[0]).unwrap();
    let receiver_pubkey = receiver_key.to_keypair(&secp).public_key();

    // MultisigProver: Creates an unsigned withdrawal transaction
    let multisig_utxo = UTXO {
        txid: peg_in.compute_txid(),
        vout: 0,
        txout: peg_in.output[0].clone(),
    };
    let (unsigned_peg_out, sighash) = MultisigProver::create_peg_out_tx(
        vec![multisig_utxo],
        Amount::from_sat(5000),
        &receiver_pubkey,
        &script,
    );

    // Get signatures for the withdrawal from each member of the committee
    let mut committee_signatures: HashMap<usize, Signature> = HashMap::new();
    for i in 0..COMMITTEE_SIZE {
        committee_signatures.insert(i, validators[i].sign_sighash(&sighash, &secp));
    }

    // MultisigProver: Collect signatures, fill in missing signatures, add control block and finalize witness
    let peg_out = MultisigProver::finalize_tx_witness(
        unsigned_peg_out,
        &committee_signatures,
        &script,
        &internal_key,
        &secp,
    );

    // Test peg in and peg out transactions for mempool acceptance and submit them
    test_and_submit(&rpc, [peg_in, peg_out], address);
}
