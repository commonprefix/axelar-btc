use bitcoin::key::rand;
use bitcoin::Address;
use bitcoincore_rpc::{Auth, Client, RawTx, RpcApi};
use num_bigint::BigUint;
use num_traits::ops::bytes::ToBytes;
use std::str::FromStr;
use std::{collections::BTreeMap, path::PathBuf, fs, path};

use bitcoin::{
    amount::Amount,
    bip32::{DerivationPath, KeySource, Xpriv, Xpub},
    blockdata::{locktime::absolute::LockTime, script, transaction, witness::Witness},
    key::{Secp256k1, UntweakedPublicKey},
    opcodes::all::{
        OP_ADD, OP_CHECKSIG, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_GREATERTHANOREQUAL,
        OP_IF, OP_SWAP,
    },
    taproot::{LeafVersion, TaprootBuilder},
    Network, Psbt, ScriptBuf, TapLeafHash, XOnlyPublicKey,
};

const WALLET: &str = "default";

fn create_op_return() -> ScriptBuf {
    let data = b"ethereum:0x0000000000000000000000000000000000000000:foobar";
    ScriptBuf::new_op_return(data)
}

fn create_multisig_script(committee_keys: &Vec<Xpriv>) -> ScriptBuf {
    let secp = Secp256k1::new();
    let mut script = script::Builder::new().push_int(0);
    for i in 0..committee_keys.len() {
        script = script
            .push_opcode(OP_SWAP)
            .push_opcode(OP_DUP)
            .push_int(0)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF) // IF empty signature
            .push_opcode(OP_DROP) // drop empty signature
            .push_opcode(OP_ELSE) // ELSE verify non-empty signature
            .push_x_only_key(
                &committee_keys[COMMITTEE_SIZE - 1 - i]
                    .to_keypair(&secp)
                    .x_only_public_key()
                    .0,
            )
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_IF)
            // Each committee member has weight equal to its index + 1
            .push_int(1)
            .push_opcode(OP_ELSE)
            .push_int(0)
            .push_opcode(OP_ENDIF) // ENDIF valid signature
            .push_opcode(OP_ADD)
            .push_opcode(OP_ENDIF); // ENDIF empty signature
    }
    script = script.push_int(2).push_opcode(OP_GREATERTHANOREQUAL);

    script.into_script()
}

fn create_unspendable_internal_key() -> XOnlyPublicKey {
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

const COMMITTEE_SIZE: usize = 75;
const NETWORK: Network = Network::Regtest;
// $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest listtransactions "*" 101 100
// get txid
// $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest gettransaction <txid> true true
// get hex and build coinbase_tx from it:

fn create_peg_in_tx(
    coinbase_tx: &transaction::Transaction,
    coinbase_vout: &usize,
    committee_keys: &Vec<Xpriv>,
    rpc: &Client,
) -> transaction::Transaction {
    let secp = Secp256k1::new();
    let tx_in = transaction::TxIn {
        previous_output: transaction::OutPoint {
            txid: coinbase_tx.compute_txid(),
            vout: u32::try_from(*coinbase_vout).unwrap(),
        },
        script_sig: script::ScriptBuf::new(),
        sequence: transaction::Sequence::MAX,
        witness: Witness::new(),
    };

    let script = create_multisig_script(&committee_keys);
    let internal_key = create_unspendable_internal_key();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();

    let tx_script_pubkey = script::ScriptBuf::new_p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
    );

    let tx_out = transaction::TxOut {
        value: Amount::from_str("49.9999 BTC").unwrap(),
        script_pubkey: tx_script_pubkey.clone(),
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

fn create_peg_out_tx(
    signed_peg_in_tx: &transaction::Transaction,
    committee_keys: &Vec<Xpriv>,
    validator_index: usize,
) -> Psbt {
    let secp = Secp256k1::new();
    let script = create_multisig_script(committee_keys);

    // Build peg-out tx that spends peg-in tx
    let peg_out_tx_in = transaction::TxIn {
        previous_output: transaction::OutPoint {
            txid: signed_peg_in_tx.compute_txid(),
            vout: 0,
        },
        script_sig: script::ScriptBuf::new(),
        sequence: transaction::Sequence::MAX,
        witness: Witness::default(),
    };

    let receiver_key = Xpriv::new_master(NETWORK, &[0]).unwrap();
    let receiver_pubkey = receiver_key.to_keypair(&secp).public_key();
    let internal_key = create_unspendable_internal_key();

    let peg_in_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();

    // let peg_out_taproot_spend_info = TaprootBuilder::new()
    //     // as per https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs, bullet 4
    //     .add_leaf(0, script::Builder::new().into_script())
    //     .unwrap()
    //     .finalize(&secp, receiver_pubkey.to_x_only_pub())
    //     .unwrap();

    let p2pk = ScriptBuf::new_p2pk(&receiver_pubkey.into());

    // let peg_out_tx_script_pubkey = script::ScriptBuf::new_p2tr(
    //     &secp,
    //     peg_out_taproot_spend_info.internal_key(),
    //     peg_out_taproot_spend_info.merkle_root(),
    // );

    let unsigned_peg_out_tx = transaction::Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![peg_out_tx_in],
        output: vec![transaction::TxOut {
            value: Amount::from_str("49.998 BTC").unwrap(),
            script_pubkey: p2pk,
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_peg_out_tx.clone()).unwrap();
    psbt.inputs[0].witness_utxo = Some(signed_peg_in_tx.output[0].to_owned());
    psbt.inputs[0].tap_key_origins =
        BTreeMap::<bitcoin::XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>::new();
    psbt.inputs[0].tap_key_origins.insert(
        committee_keys[validator_index]
            .to_keypair(&secp)
            .x_only_public_key()
            .0,
        (
            vec![script.tapscript_leaf_hash()],
            (
                Xpub::from_priv(&secp, &committee_keys[validator_index]).fingerprint(),
                DerivationPath::default(),
            ),
        ),
    );

    psbt.inputs[0].tap_scripts = BTreeMap::new();
    psbt.inputs[0].tap_scripts.insert(
        peg_in_taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap(),
        (script.to_owned(), LeafVersion::TapScript),
    );

    psbt.sign(&committee_keys[validator_index], &secp).unwrap();

    return psbt;
}

fn finalize_psbt(mut psbt: Psbt, committee_keys: &Vec<Xpriv>) -> transaction::Transaction {
    let secp = Secp256k1::new();

    let script = create_multisig_script(&committee_keys);
    let internal_key = create_unspendable_internal_key();
    let peg_in_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();

    let mut script_witness = Witness::new();
    for i in 0..COMMITTEE_SIZE {
        let signature_option = psbt.inputs[0].tap_script_sigs.get(&(
            committee_keys[i].to_keypair(&secp).x_only_public_key().0,
            script.tapscript_leaf_hash(),
        ));
        if let Some(signature) = signature_option {
            script_witness.push(signature.to_vec());
        } else {
            script_witness.push(&[]);
        }
    }
    for (control_block, (script, _)) in psbt.inputs[0].tap_scripts.iter() {
        script_witness.push(script.to_bytes());
        script_witness.push(control_block.serialize());
    }
    psbt.inputs[0].final_script_witness = Some(script_witness);
    psbt.inputs[0].tap_merkle_root = peg_in_taproot_spend_info.merkle_root();
    psbt.inputs[0].partial_sigs = BTreeMap::new();
    psbt.inputs[0].sighash_type = None;
    psbt.inputs[0].redeem_script = None;
    psbt.inputs[0].witness_script = None;
    psbt.inputs[0].bip32_derivation = BTreeMap::new();
    psbt.inputs[0].tap_script_sigs = BTreeMap::new();
    psbt.inputs[0].tap_scripts = BTreeMap::new();
    psbt.inputs[0].tap_key_sig = None;

    psbt.extract_tx().unwrap()
}

fn init_wallet(rpc: &Client) -> (Address, transaction::Transaction, usize) {
    let random_number = rand::random::<usize>().to_string();
    let random_label = random_number.as_str();

    let _ = rpc
        .create_wallet(WALLET, None, None, None, None)
        .unwrap();
    let _ = rpc.load_wallet(WALLET);

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest getnewaddress
    let address = rpc
        .get_new_address(Some(random_label), None)
        .unwrap()
        .require_network(NETWORK)
        .unwrap();

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest generatetoaddress 101 <previous_output>
    rpc.generate_to_address(101, &address).unwrap();

    // let coinbase_txid = rpc
    //     .send_to_address(
    //         &address,
    //         Amount::from_int_btc(60),
    //         None,
    //         None,
    //         None,
    //         None,
    //         None,
    //         None,
    //     )
    //     .unwrap();

    // rpc.generate_to_address(1, &address).unwrap();

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

fn main() {
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::CookieFile(PathBuf::from("/home/themicp/.bitcoin/regtest/.cookie")), // TODO: don't hardcode this
    )
    .unwrap();
    let (address, coinbase_tx, coinbase_vout) = init_wallet(&rpc);

    let mut committee_keys = vec![];
    for i in 0..COMMITTEE_SIZE {
        committee_keys.push(Xpriv::new_master(NETWORK, &[i.try_into().unwrap()]).unwrap());
    }

    let peg_in = create_peg_in_tx(&coinbase_tx, &coinbase_vout, &committee_keys, &rpc);
    let mut psbt = create_peg_out_tx(&peg_in, &committee_keys, 0);
    for i in 1..COMMITTEE_SIZE {
        let current_psbt = create_peg_out_tx(&peg_in, &committee_keys, i);
        psbt.combine(current_psbt).unwrap();
    }

    let tx = finalize_psbt(psbt, &committee_keys);
    let result = rpc.test_mempool_accept(&[peg_in.raw_hex(), tx.raw_hex()]);
    match result {
        Err(error) => {
            println!("{:#?}", error);
            println!(
                "Result for peg-in: {:#?}",
                rpc.test_mempool_accept(&[peg_in.raw_hex()])
            );
            println!(
                "Result for peg-out: {:#?}",
                rpc.test_mempool_accept(&[tx.raw_hex()])
            );
        }
        Ok(response) => {
            assert!(response[0].allowed, "Peg in transaction failed");
            assert!(response[1].allowed, "Peg out transaction failed");
            println!(
                "Peg In: {:#?}",
                rpc.send_raw_transaction(peg_in.raw_hex()).unwrap()
            );
            println!(
                "Peg Out: {:#?}",
                rpc.send_raw_transaction(tx.raw_hex()).unwrap()
            );
            println!(
                "Mined new block: {:#?}",
                rpc.generate_to_address(1, &address).unwrap()
            );
        }
    }
}
