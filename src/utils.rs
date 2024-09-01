use std::{
    cmp::min,
    collections::{BTreeMap, HashMap},
    env,
    path::PathBuf,
};

use bitcoin::{
    bip32::Xpriv,
    key::{rand, Secp256k1},
    secp256k1::All,
    taproot::Signature,
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, TapSighash, Transaction, TxOut,
    XOnlyPublicKey,
};
use bitcoin_rs::{key::UnspendableKey, script::MultisigScript, transaction::WitnessControl};
use bitcoincore_rpc::{Auth, Client, RawTx, RpcApi};
use itertools::Itertools;
use multisig_prover::VerifierSet;
use serde::Deserialize;
use validator::Validator;

use crate::{
    multisig_prover::{self, MultisigProver, MultisigProverConfig},
    user::User,
    validator,
};

pub const SIG_SIZE: usize = 64; // Schnorr sig size (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification)
const REST_SCRIPT_SIZE: usize = 42; // TODO: replace with sth that isn't the answer to everything
const FIXED_INPUT_OVERHEAD: usize = 42; // TODO: replace with sth that isn't the answer to everything
const MAX_BTC_INT: i64 = 0x7fffffff;

#[derive(Clone)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

#[derive(Deserialize)]
struct BitcoinMaintainersResponse {
    maintainers: Vec<String>,
    time_spent: u32,
}

#[derive(Deserialize)]
struct AllValidatorsResponse {
    data: Vec<Validator>,
}

pub fn create_op_return() -> ScriptBuf {
    let data = b"ethereum:0x0000000000000000000000000000000000000000:foobar";
    ScriptBuf::new_op_return(data)
}

pub fn init_wallet(
    bitcoin_dir: &String,
    rpc: &Client,
    network: Network,
    wallet: &str,
) -> (Address, transaction::Transaction, u32) {
    let random_number = rand::random::<usize>().to_string();
    let random_label = random_number.as_str();

    let _ = rpc.create_wallet(&(bitcoin_dir.to_owned() + wallet), None, None, None, None);
    let _ = rpc.load_wallet(&(bitcoin_dir.to_owned() + wallet));

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest getnewaddress
    let address = rpc
        .get_new_address(Some(random_label), None)
        .unwrap()
        .require_network(network)
        .unwrap();

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest generatetoaddress 101 <previous_output>
    rpc.generate_to_address(101, &address).unwrap();

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest listtransactions "*" 101 100
    let coinbase_txid = rpc
        .list_transactions(Some(random_label), Some(101), Some(100), None)
        .unwrap()[0]
        .info
        .txid;

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest gettransaction <txid> true true
    let coinbase_tx = rpc
        .get_transaction(&coinbase_txid, None)
        .unwrap()
        .transaction()
        .unwrap();

    let coinbase_vout = 0;

    (address, coinbase_tx, coinbase_vout)
}

pub fn test_and_submit(
    rpc: &Client,
    txs: Vec<transaction::Transaction>,
    miner_address: Address,
) -> () {
    let result =
        rpc.test_mempool_accept(&txs.iter().map(|tx| tx.raw_hex()).collect::<Vec<String>>());

    let mempool_failure = || {
        println!("Mempool acceptance test failed. Try manually testing for mempool acceptance using the bitcoin cli for more information, with the following transactions:");
        for (i, tx) in txs.iter().enumerate() {
            println!("Transaction #{}: {}", i + 1, tx.raw_hex());
        }
    };

    match result {
        Err(error) => {
            println!("{:#?}", error);
            mempool_failure();
        }
        Ok(response) => {
            if !response[0].allowed || !response[1].allowed {
                mempool_failure();
                return;
            }

            for (i, tx) in txs.iter().enumerate() {
                println!(
                    "Transaction #{}: {}",
                    i + 1,
                    rpc.send_raw_transaction(tx.raw_hex()).unwrap()
                );
            }
            println!(
                "Mined new block: {:#?}",
                rpc.generate_to_address(1, &miner_address).unwrap()
            );
        }
    }
}

pub fn handover_input_size(sigs: usize) -> usize {
    // TODO: check me
    SIG_SIZE * sigs + REST_SCRIPT_SIZE + FIXED_INPUT_OVERHEAD
}

pub fn get_private_key(seed: usize, network: Network) -> Option<Xpriv> {
    Some(Xpriv::new_master(network, &[seed.try_into().unwrap()]).unwrap())
}

pub fn load_axelar_validators() -> Vec<Validator> {
    let client = reqwest::blocking::Client::new();

    let all_validators_response_str = client
        .get("https://api.axelarscan.io/validator/getValidators")
        .send()
        .expect("Did not receive response on request for validators")
        .text()
        .expect("Could not extract validators");

    let all_validators_response: AllValidatorsResponse =
        serde_json::from_str(&all_validators_response_str).expect("Could not parse validators");

    all_validators_response.data
}

pub fn load_bitcoin_maintainers() -> Vec<Validator> {
    let client = reqwest::blocking::Client::new();
    let axelar_validators = load_axelar_validators();

    let bitcoin_maintainers_response_str = client
        .post("https://api.axelarscan.io/validator/getChainMaintainers")
        .json(&HashMap::from([("chain", "avalanche")])) // TODO: change `avalanche` to `bitcoin`
        .send()
        .expect("Did not receive response on request for chain maintainers")
        .text()
        .expect("Could not extract chain maintainers");

    let bitcoin_maintainers_response: BitcoinMaintainersResponse =
        serde_json::from_str(&bitcoin_maintainers_response_str)
            .expect("Could not parse chain maintainers");
    let mut bitcoin_maintainers_addresses = bitcoin_maintainers_response.maintainers;

    bitcoin_maintainers_addresses.sort_unstable();

    let bitcoin_maintainers = axelar_validators
        .into_iter()
        .filter(|x| {
            bitcoin_maintainers_addresses
                .binary_search(&x.operator_address)
                .is_ok()
        })
        .collect::<Vec<_>>();

    bitcoin_maintainers
}

fn set_threshold_and_weights(validators: &mut Vec<Validator>) -> i64 {
    let mut threshold = validators.iter().map(|x| x.weight).sum::<i64>() / 3 * 2;
    // keep truncating LSBs until threshold fits in 32 bits
    // TODO: optimization:
    // find the exact extra bits with math on threshold and round instead of truncating
    while threshold > MAX_BTC_INT {
        let mut new_threshold = 0;
        for val in validators.iter_mut() {
            val.weight >>= 1;
            new_threshold += val.weight;
        }
        threshold = new_threshold / 3 * 2;
    }

    threshold
}

pub fn get_multisig_setup() -> (Vec<Validator>, i64) {
    let mut bitcoin_maintainers = load_bitcoin_maintainers();

    let threshold = set_threshold_and_weights(&mut bitcoin_maintainers);

    (bitcoin_maintainers, threshold)
}

pub fn collect_signatures(
    sighashes: &Vec<TapSighash>,
    validators: &Vec<Validator>,
    secp: &Secp256k1<All>,
) -> Vec<Vec<Option<Signature>>> {
    // Get signatures for the withdrawal from each member of the committee
    let mut committee_signatures = vec![];
    for i in 0..sighashes.len() {
        let mut committee_signatures_per_sighash = vec![];
        for validator in validators.clone() {
            // Missing signatures should be represented with None. Order matters.
            committee_signatures_per_sighash
                .push(Some(validator.sign_sighash(&sighashes[i], secp)));
        }
        committee_signatures.push(committee_signatures_per_sighash);
    }
    committee_signatures
}

// Copied from multisig-prover
fn signers_symetric_difference_count(
    s1: &BTreeMap<String, String>,
    s2: &BTreeMap<String, String>,
) -> usize {
    signers_difference_count(s1, s2).saturating_add(signers_difference_count(s2, s1))
}

fn signers_difference_count(s1: &BTreeMap<String, String>, s2: &BTreeMap<String, String>) -> usize {
    s1.values().filter(|v| !s2.values().contains(v)).count()
}

pub fn should_update_verifier_set(
    new_verifier_set: &VerifierSet,
    old_verifier_set: &VerifierSet,
    threshold: usize,
) -> bool {
    signers_symetric_difference_count(&new_verifier_set.signers, &old_verifier_set.signers)
        >= threshold
}

pub fn parse_args() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run <bitcoin_directory>");
        std::process::exit(1);
    }
    args[1].to_owned() + "/regtest/"
}

pub fn init_rpc_client(bitcoin_dir: &String, cookie_filename: &str) -> Client {
    Client::new(
        "http://127.0.0.1:18443",
        Auth::CookieFile(PathBuf::from(&(bitcoin_dir.to_owned() + cookie_filename))),
    )
    .unwrap()
}

pub fn setup_validators(N: usize, network: Network) -> (Vec<Validator>, VerifierSet, i64) {
    let (mut validators, mut threshold) = get_multisig_setup();
    validators = validators[0..min(N, validators.len())].to_vec();
    threshold = 1; // For testing purposes

    for (i, validator) in validators.iter_mut().enumerate() {
        validator.key = get_private_key(i, network);
    }

    let verifier_set = VerifierSet {
        signers: validators
            .iter()
            .map(|v| (v.operator_address.clone(), v.operator_address.clone()))
            .collect(),
    };

    (validators, verifier_set, threshold)
}

// Creates a multisig script with the given validators and threshold.
pub fn create_multisig_script(
    validators: &Vec<Validator>,
    threshold: i64,
    secp: &Secp256k1<All>,
) -> (ScriptBuf, ScriptBuf) {
    let validators_pks_weights: Vec<_> = validators
        .iter()
        .map(|v| (v.public_key(&secp), v.weight))
        .collect();

    let internal_key = XOnlyPublicKey::create_unspendable_key();
    ScriptBuf::create_threshold_multisig_with_weights(
        &validators_pks_weights,
        &internal_key,
        threshold,
        &secp,
    )
}

/// User creates a deposit transaction (peg-in).
pub fn user_deposit(
    coinbase_tx: &Transaction,
    coinbase_vout: u32,
    script_pubkey: &ScriptBuf,
    rpc: &Client,
) -> Transaction {
    let user_utxo = Utxo {
        outpoint: OutPoint {
            txid: coinbase_tx.compute_txid(),
            vout: coinbase_vout,
        },
        txout: coinbase_tx.output[0].clone(),
    };
    User::peg_in(user_utxo, script_pubkey, rpc)
}

pub fn init_multisig_prover(verifier_set: &VerifierSet) -> MultisigProver {
    MultisigProver {
        available_utxos: vec![], // Will be populated later
        verifier_set: verifier_set.clone(),
        config: MultisigProverConfig {
            verifier_set_diff_threshold: 1,
        },
    }
}

pub fn create_handover_transactions(
    multisig_prover: &mut MultisigProver,
    old_validators: &Vec<Validator>,
    secp: &Secp256k1<All>,
    old_script: &ScriptBuf,
    new_script_pubkey: &ScriptBuf,
    new_verifier_set: &VerifierSet,
) -> Vec<Transaction> {
    let handover_option = multisig_prover.create_handover_tx(
        2,
        100_000,
        Amount::from_sat(1_000),
        Amount::from_sat(1),
        old_script,
        new_script_pubkey,
        &new_verifier_set,
    );

    let mut unsigned_handovers = handover_option.expect("Handover failed");

    multisig_prover.verifier_set = new_verifier_set.clone();

    unsigned_handovers
        .iter_mut()
        .map(|(tx, sighashes)| {
            let committee_signatures = collect_signatures(&sighashes, old_validators, &secp);
            tx.finalize_witness(
                &committee_signatures,
                old_script,
                &XOnlyPublicKey::create_unspendable_key(),
                &secp,
            );
            tx.clone()
        })
        .collect()
}

pub fn create_address(secp: &Secp256k1<All>, network: Network) -> Address {
    let receiver_key = Xpriv::new_master(network, &[0]).unwrap();
    let receiver_pubkey = receiver_key.to_keypair(secp).public_key();
    Address::p2pkh(bitcoin::PublicKey::from(receiver_pubkey), network)
}

pub fn create_peg_out_transaction(
    multisig_prover: &mut MultisigProver,
    validators: &Vec<Validator>,
    secp: &Secp256k1<All>,
    script: &ScriptBuf,
    script_pubkey: &ScriptBuf,
    network: Network,
) -> Transaction {
    let (mut peg_out, sighashes) = multisig_prover.create_peg_out_tx(
        Amount::from_sat(5_000),
        vec![(
            multisig_prover.available_utxos[0].txout.value / 2,
            create_address(secp, network),
        )],
        script,
        script_pubkey,
    );

    let committee_signatures = collect_signatures(&sighashes, validators, &secp);
    peg_out.finalize_witness(
        &committee_signatures,
        script,
        &XOnlyPublicKey::create_unspendable_key(),
        &secp,
    );

    peg_out
}

pub fn update_multisig_prover_utxos(tx: &Vec<Transaction>, multisig_prover: &mut MultisigProver) {
    multisig_prover.available_utxos = tx
        .iter()
        .flat_map(|tx| {
            tx.output
                .iter()
                .filter(|txout| !txout.script_pubkey.is_op_return())
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
}
