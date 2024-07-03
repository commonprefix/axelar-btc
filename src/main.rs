use axelar_btc::{
    collect_signatures, create_op_return, get_multisig_setup, get_private_key, handover_input_size,
    init_wallet, test_and_submit, Utxo, SIG_SIZE,
};
use bitcoin::{key::Secp256k1, Network};
use bitcoin::{OutPoint, ScriptBuf, XOnlyPublicKey};
use bitcoin_rs::key::UnspendableKey;
use bitcoin_rs::script::MultisigScript;
use bitcoincore_rpc::{Auth, Client};
use multisig_prover::MultisigProver;
use std::{env, path::PathBuf};
use user::User;

use bitcoin::{amount::Amount, bip32::Xpriv};
mod multisig_prover;
mod user;

const WALLET: &str = "wallets/default";
const COOKIE: &str = ".cookie";
const NETWORK: Network = Network::Regtest;

fn main() {
    let (mut validators, threshold) = get_multisig_setup();

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

    // Create validators' private keys
    for (i, validator) in validators.iter_mut().enumerate() {
        validator.key = get_private_key(i, NETWORK);
    }

    // Store the public keys & weights of the validators
    let secp = Secp256k1::new();

    let validators_pks_weights = validators
        .iter()
        .map(|x| (x.public_key(&secp), x.weight))
        .collect::<Vec<_>>();

    // Create the multisig bitcoin script and an internal unspendable key
    let internal_key = XOnlyPublicKey::create_unspendable_key();
    let (script, script_pubkey) = ScriptBuf::create_threshold_multisig_with_weights(
        &validators_pks_weights,
        &internal_key,
        threshold,
        &secp,
    );

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

    // Initialize MultisigProver
    let mut multisig_prover = MultisigProver {
        available_utxos: vec![
            Utxo {
                outpoint: OutPoint {
                    txid: peg_in.compute_txid(),
                    vout: 0,
                },
                txout: peg_in.output[0].clone(),
            },
            Utxo {
                outpoint: OutPoint {
                    txid: peg_in.compute_txid(),
                    vout: 1,
                },
                txout: peg_in.output[0].clone(),
            },
        ],
    };

    // MultisigProver: Handover existing UTXOs to new multisig committee
    let unsigned_handovers = multisig_prover.create_handover_tx(
        2,
        100000,
        Amount::from_sat(1000),
        Amount::from_sat(1),
        &script,
        &script_pubkey, // using the old committee again for simplicity
    );

    let mut handover_txs: Vec<bitcoin::Transaction> = unsigned_handovers
        .iter()
        .map(|(tx, sighashes)| {
            // Get signatures for the withdrawal from each member of the committee
            let committee_signatures = collect_signatures(&sighashes, &validators, &secp);

            multisig_prover.finalize_tx_witness(
                tx.clone(),
                &committee_signatures,
                &script,
                &internal_key,
                &secp,
            )
        })
        .collect();

    // MultisigProver: Update available_utxos
    multisig_prover.available_utxos = handover_txs
        .iter()
        .flat_map(|tx| {
            tx.output
                .iter()
                .enumerate()
                .map(|(i, txout)| Utxo {
                    outpoint: OutPoint {
                        txid: tx.compute_txid(),
                        vout: i as u32,
                    },
                    txout: txout.clone(),
                })
                .collect::<Vec<Utxo>>()
        })
        .collect();

    // MultisigProver: Creates an unsigned withdrawal transaction
    let (unsigned_peg_out, sighashes) = multisig_prover.create_peg_out_tx(
        Amount::from_sat(5000),
        vec![(
            multisig_prover.available_utxos[0].txout.value / 2,
            receiver_pubkey.clone(),
        )],
        &script,
        &script_pubkey,
    );

    // Get signatures for the withdrawal from each member of the committee
    let committee_signatures = collect_signatures(&sighashes, &validators, &secp);

    // MultisigProver: Collect signatures, fill in missing signatures, add control block and finalize witness
    let peg_out = multisig_prover.finalize_tx_witness(
        unsigned_peg_out,
        &committee_signatures,
        &script,
        &internal_key,
        &secp,
    );

    // let demo_outputs: Vec<Utxo> = vec![
    //     Utxo {
    //         outpoint: OutPoint {
    //             txid: coinbase_tx.compute_txid(),
    //             vout: 0,
    //         },
    //         txout: TxOut {
    //             value: Amount::from_sat(0),
    //             script_pubkey: ScriptBuf::default(),
    //         },
    //     },
    //     Utxo {
    //         outpoint: OutPoint {
    //             txid: coinbase_tx.compute_txid(),
    //             vout: 1,
    //         },
    //         txout: TxOut {
    //             value: Amount::from_sat(1),
    //             script_pubkey: ScriptBuf::default(),
    //         },
    //     },
    //     Utxo {
    //         outpoint: OutPoint {
    //             txid: coinbase_tx.compute_txid(),
    //             vout: 2,
    //         },
    //         txout: TxOut {
    //             value: Amount::from_sat(2),
    //             script_pubkey: ScriptBuf::default(),
    //         },
    //     },
    //     Utxo {
    //         outpoint: OutPoint {
    //             txid: coinbase_tx.compute_txid(),
    //             vout: 3,
    //         },
    //         txout: TxOut {
    //             value: Amount::from_sat(3),
    //             script_pubkey: ScriptBuf::default(),
    //         },
    //     },
    // ];

    // Test transactions for mempool acceptance and submit them
    let mut txs = vec![peg_in];
    txs.append(&mut handover_txs);
    txs.push(peg_out);
    test_and_submit(&rpc, txs, address);
}
