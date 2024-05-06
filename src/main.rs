use std::str::FromStr;
use std::collections::BTreeMap;
use num_traits::ops::bytes::ToBytes;
use num_bigint::BigUint;

use bitcoin::{
    Network,
    TapLeafHash,
    blockdata::{
        transaction,
        locktime::absolute::LockTime,
        script,
        witness::Witness,
        opcodes::all::{
            OP_CHECKSIG, OP_IF,
            OP_ELSE, OP_ENDIF,
            OP_SWAP, OP_ADD, OP_GREATERTHAN
        },
    },
    amount::Amount,
    taproot::{TaprootBuilder, LeafVersion},
    key::{Secp256k1, UntweakedPublicKey},
    bip32::{Xpriv, Xpub, DerivationPath, Fingerprint},
    Psbt,
    psbt,
    consensus::encode::{serialize_hex, deserialize_hex},
};

fn main() {
    const COMMITTEE_SIZE: usize = 10;

    const NETWORK: Network = Network::Regtest;

    let mut committee_keys: Vec<_> = vec![];
    for i in 0..COMMITTEE_SIZE {
        committee_keys.push(
            Xpriv::new_master(NETWORK, &[i.try_into().unwrap()]).unwrap()
        );
    }

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest listtransactions "*" 101 100
    // get txid
    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest gettransaction <txid> true true
    // get hex and build coinbase_tx from it
    let coinbase_tx = deserialize_hex::<transaction::Transaction>(
        "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a0100000016001453704b1be1c39c398a76e68f3bf4bcb45dece5e60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"
    ).unwrap();

    let peg_in_tx_in = transaction::TxIn {
        previous_output: transaction::OutPoint {
            txid: coinbase_tx.compute_txid(),
            vout: 0,
        },
        script_sig: script::ScriptBuf::new(),
        sequence: transaction::Sequence::MAX,
        witness: Witness::new(),
    };

    let secp = Secp256k1::new();

    let mut script = script::Builder::new()
        .push_key(&committee_keys[0].to_keypair(&secp).public_key().into())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_IF)
        // Each committee member has weight equal to its index + 1
        .push_int(1)
        .push_opcode(OP_ELSE)
        .push_int(0)
        .push_opcode(OP_ENDIF);

    for i in 1..COMMITTEE_SIZE {
        script = script
            .push_opcode(OP_SWAP)
            .push_key(&committee_keys[i].to_keypair(&secp).public_key().into())
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_IF)
            // Each committee member has weight equal to its index + 1
            .push_int((i+1).try_into().unwrap())
            .push_opcode(OP_ADD)
            .push_opcode(OP_ENDIF);
    }

    script = script
        .push_int(
            (1..=COMMITTEE_SIZE).sum::<usize>().try_into().unwrap()
        )
        .push_opcode(OP_GREATERTHAN);

    let script = script.into_script();

    // the Gx of secp256k1, incremented till a valid x is found
    // See
    // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs,
    // bullet 3, for a proper way to choose such a key
    let nothing_up_my_sleeve_key = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62,
        0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE,
        0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x99,
    ];
    let mut int_key = BigUint::from_bytes_be(&nothing_up_my_sleeve_key);
    while let Err(_) = UntweakedPublicKey::from_slice(&int_key.to_be_bytes()) {
        int_key += 1u32;
    }
    let internal_key = UntweakedPublicKey::from_slice(
        &int_key.to_be_bytes()
    ).unwrap();

    let peg_in_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script).unwrap()
        .finalize(&secp, internal_key).unwrap();

    let script_pubkey = script::ScriptBuf::new_p2tr(
        &secp,
        peg_in_taproot_spend_info.internal_key(),
        peg_in_taproot_spend_info.merkle_root(),
    );

    let peg_in_tx_out = transaction::TxOut {
        value: Amount::from_str("49.9999 BTC").unwrap(),
        script_pubkey,
    };

    let unsigned_peg_in_tx = transaction::Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![peg_in_tx_in],
        output: vec![peg_in_tx_out],
    };

    println!("unsigned peg-in tx: {:?}", serialize_hex(&unsigned_peg_in_tx));

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest signrawtransactionwithwallet <serialized unsigned_peg_in_tx>
    // get hex and build peg_in_tx from it
    let signed_peg_in_tx = deserialize_hex::<transaction::Transaction>("02000000000101f3c5b238642036b061431c72e658993eec62b421eac83ea10033b07c5dc2e8bd0000000000ffffffff01f0ca052a0100000022512082082dd5929070b7c5b6b0891a40fe8960e00a82a96ca52e4f7db800b3acbb4e0247304402200c221ae75f7717e834f628bb94fc4c90342c413402123c0a496dbed422d6985202206a3b1acb8d69b62c0f439a658c9dc6fac61b2ec7894c01210d7c44663c813e61012103b27c59233c02acb35b1af0b823f9140301210183177050bff400601f7ca761d700000000").unwrap();

    // $ bitcoin-core.cli -rpcport=18443 -rpcpassword=1234 -regtest testmempoolaccept '["<serialized signed_peg_in_tx>"]'
    // ensure result contains `"allowed": true`
}
