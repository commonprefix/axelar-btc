use bitcoin::{
    key::{rand, Secp256k1, UntweakedPublicKey},
    opcodes::all::{OP_ADD, OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_GREATERTHANOREQUAL, OP_IF, OP_SWAP},
    script,
    secp256k1::All,
    taproot::TaprootBuilder,
    transaction, Address, Network, ScriptBuf, XOnlyPublicKey,
};
use bitcoincore_rpc::{Client, RawTx, RpcApi};
use num_bigint::BigUint;
use num_traits::ops::bytes::ToBytes;

pub fn create_op_return() -> ScriptBuf {
    let data = b"ethereum:0x0000000000000000000000000000000000000000:foobar";
    ScriptBuf::new_op_return(data)
}

pub fn create_multisig_script(
    validators_pks: &Vec<(XOnlyPublicKey, i64)>,
    internal_key: XOnlyPublicKey,
    threshold: i64,
    secp: &Secp256k1<All>,
) -> (ScriptBuf, ScriptBuf) {
    let mut builder = script::Builder::new().push_int(0); // TODO: the first signature could initialize the accumulator
    for (key, weight) in validators_pks.iter() {
        builder = builder
            .push_opcode(OP_SWAP)
            .push_x_only_key(&key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_IF)
            // Each committee member has weight equal to its index + 1
            .push_int(*weight)
            .push_opcode(OP_ELSE)
            .push_int(0)
            .push_opcode(OP_ENDIF) // ENDIF valid signature
            .push_opcode(OP_ADD);
    }
    builder = builder
        .push_int(threshold)
        .push_opcode(OP_GREATERTHANOREQUAL);
    let script = builder.into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();

    let script_pubkey = script::ScriptBuf::new_p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
    );

    (script, script_pubkey)
}

pub fn create_unspendable_internal_key() -> XOnlyPublicKey {
    // the Gx of SECP, incremented till a valid x is found
    // See
    // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs,
    // bullet 3, for a proper way to choose such a key
    let nothing_up_my_sleeve_key = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x99,
    ];
    let mut int_key = BigUint::from_bytes_be(&nothing_up_my_sleeve_key);
    while let Err(_) = UntweakedPublicKey::from_slice(&int_key.to_be_bytes()) {
        int_key += 1u32;
    }
    let internal_key = UntweakedPublicKey::from_slice(&int_key.to_be_bytes()).unwrap();

    internal_key
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
    txs: [transaction::Transaction; 2],
    miner_address: Address,
) -> () {
    let peg_in = txs[0].clone();
    let peg_out = txs[1].clone();
    let result = rpc.test_mempool_accept(&[peg_in.raw_hex(), peg_out.raw_hex()]);

    let mempool_failure = || {
        println!("Mempool acceptance test failed. Try manually testing for mempool acceptance using the bitcoin cli for more information, with the following transactions:");
        println!("Peg in: {}", peg_in.raw_hex());
        println!("Peg out: {}", peg_out.raw_hex());
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

            println!(
                "Peg In: {:#?}",
                rpc.send_raw_transaction(peg_in.raw_hex()).unwrap()
            );
            println!(
                "Peg Out: {:#?}",
                rpc.send_raw_transaction(peg_out.raw_hex()).unwrap()
            );
            println!(
                "Mined new block: {:#?}",
                rpc.generate_to_address(1, &miner_address).unwrap()
            );
        }
    }
}

const SIG_SIZE: usize = 64; // Schnorr sig size (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification)
const REST_SCRIPT_SIZE: usize = 42; // TODO: replace with sth that isn't the answer to everything
const FIXED_INPUT_OVERHEAD: usize = 42; // TODO: replace with sth that isn't the answer to everything
pub fn handover_input_size(sigs: usize, placeholders: usize) -> usize {
    // TODO: check me
    SIG_SIZE * sigs + placeholders + REST_SCRIPT_SIZE + FIXED_INPUT_OVERHEAD
}