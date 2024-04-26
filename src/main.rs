use std::collections::HashMap;
use num_traits::ops::bytes::ToBytes;
use num_bigint::BigUint;

use bitcoin::{
    Network,
    blockdata::{
        transaction,
        locktime::absolute::LockTime,
        script::{Builder, ScriptBuf},
        witness::Witness,
        opcodes::Opcode,
    },
    amount::Amount,
    taproot::TaprootBuilder,
    key::{Secp256k1, UntweakedPublicKey},
    bip32::Xpriv,
};

fn main() {
    const COMMITTEE_SIZE: usize = 10;

    const NETWORK: Network = Network::Regtest;

    let ops: HashMap<&str, Opcode> = HashMap::from([
        ("CHECKSIG", 0xac.into()),
        ("IF", 0x63.into()),
        ("ELSE", 0x67.into()),
        ("ENDIF", 0x68.into()),
        ("SWAP", 0x7c.into()),
        ("ADD", 0x93.into()),
        ("GREATERTHAN", 0xa0.into()),
    ]);

    let mut committee_keys: Vec<_> = vec![];
    for i in 0..COMMITTEE_SIZE {
        committee_keys.push(
            Xpriv::new_master(NETWORK, &[i.try_into().unwrap()]).unwrap()
        );
    }

    let tx_in = transaction::TxIn {
        previous_output: transaction::OutPoint::null(),
        script_sig: ScriptBuf::new(),
        sequence: transaction::Sequence::MAX,
        witness: Witness::new(),
    };

    let secp = Secp256k1::new();

    let mut script = Builder::new()
        .push_key(&committee_keys[0].to_keypair(&secp).public_key().into())
        .push_opcode(ops["CHECKSIG"])
        .push_opcode(ops["IF"])
        // Each committee member has weight equal to its index + 1
        .push_int(1)
        .push_opcode(ops["ELSE"])
        .push_int(0)
        .push_opcode(ops["ENDIF"]);

    for i in 1..COMMITTEE_SIZE {
        script = script
            .push_opcode(ops["SWAP"])
            .push_key(&committee_keys[i].to_keypair(&secp).public_key().into())
            .push_opcode(ops["CHECKSIG"])
            .push_opcode(ops["IF"])
            // Each committee member has weight equal to its index + 1
            .push_int((i+1).try_into().unwrap())
            .push_opcode(ops["ADD"])
            .push_opcode(ops["ENDIF"]);
    }

    let script = script.into_script();

    // the Gx of secp256k1, incremented till a valid x is found
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

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script).unwrap()
        .finalize(&secp, internal_key).unwrap();

    let script_pubkey = ScriptBuf::new_p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
    );

    let tx_out = transaction::TxOut {
        value: Amount::ONE_BTC,
        script_pubkey,
    };

    let peg_in_tx = transaction::Transaction {
        version: transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    println!("{peg_in_tx:?}");
}
