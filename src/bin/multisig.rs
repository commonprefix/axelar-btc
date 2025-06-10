use axelar_btc::utils::{
    create_consolidation_txs, create_handover_transactions, create_multisig_script,
    create_peg_out_transaction, init_multisig_prover, init_rpc_client, init_wallet, parse_args,
    setup_validators, test_and_submit, update_multisig_prover_utxos, user_deposit,
};
use bitcoin::{key::Secp256k1, Network};

const WALLET: &str = "wallets/default";
const COOKIE: &str = ".cookie";
const NETWORK: Network = Network::Regtest;

fn main() {
    let bitcoin_dir = parse_args();

    // Initialize the Bitcoin RPC client
    let rpc = init_rpc_client(&bitcoin_dir, &COOKIE);

    // Initialize wallet and get the initial UTXO information
    let (address, coinbase_tx, coinbase_vout) = init_wallet(&bitcoin_dir, &rpc, NETWORK, WALLET);
    println!("{}", coinbase_tx.compute_txid());
    println!("{}", coinbase_vout);
    println!("{}", address);

    // Setup validators for multisig
    let (validators, verifier_set, threshold) = setup_validators(3, NETWORK);

    // Initialize multisig prover
    let mut multisig_prover = init_multisig_prover(&verifier_set);

    let secp = Secp256k1::new();
    // Create Bitcoin Multisig script representing the validators
    let (script, script_pubkey) = create_multisig_script(&validators, threshold, &secp);
    println!("{}", script_pubkey);

    // User creates a deposit transaction
    let peg_in_tx = user_deposit(&coinbase_tx, coinbase_vout, &script_pubkey, &rpc);
    println!("{}", peg_in_tx.compute_txid());

    println!("before: {:?}", multisig_prover.available_utxos);
    // Update multisig prover with the UTXOs from the peg-in transaction
    update_multisig_prover_utxos(&vec![peg_in_tx.clone()], &mut multisig_prover);
    println!("after 1: {:?}", multisig_prover.available_utxos);

    // TODO: Simulate consolidation of UTXOs
    let mut consolidation_txs = create_consolidation_txs(
        &mut multisig_prover,
        &validators,
        &secp,
        &script,
        &script_pubkey,
    );

    println!("consolidation txs: {:?}", consolidation_txs);

    println!("before 2: {:?}", multisig_prover.available_utxos);
    // Update multisig prover with the UTXOs from the consolidation transaction
    update_multisig_prover_utxos(&consolidation_txs, &mut multisig_prover);
    println!("after 2: {:?}", multisig_prover.available_utxos);

    // Simulate a handover of the multisig to a new set of validators
    let old_validators = validators.clone();
    let old_script = script.clone();
    let (validators, verifier_set, threshold) = setup_validators(validators.len() - 1, NETWORK); // just cutting out one validator

    // Create a new multisig script with the new validators
    let (script, script_pubkey) = create_multisig_script(&validators, threshold, &secp);

    // Create handover transactions
    let mut handover_txs = create_handover_transactions(
        &mut multisig_prover,
        &old_validators,
        &secp,
        &old_script,
        &script_pubkey,
        &verifier_set,
    );

    // Update multisig prover with the UTXOs from the handover transactions
    update_multisig_prover_utxos(&handover_txs, &mut multisig_prover);

    // User creates a peg-out (withdrawal) transaction
    let peg_out_tx = create_peg_out_transaction(
        &mut multisig_prover,
        &validators,
        &secp,
        &script,
        &script_pubkey,
        NETWORK,
    );

    // Test transactions for mempool acceptance and submit them
    let mut txs = vec![peg_in_tx];
    txs.append(&mut consolidation_txs);
    txs.append(&mut handover_txs);
    txs.push(peg_out_tx);
    test_and_submit(&rpc, txs, address);
}
