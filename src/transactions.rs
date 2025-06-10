use std::str::FromStr;

use bitcoin::{
    absolute::LockTime, key::Secp256k1, script, secp256k1::Message, sighash::SighashCache,
    transaction, Address, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey, ScriptBuf,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Client, Error, RawTx, RpcApi};
use serde_json::{json, Value};

const ANCHOR_ADDRESS: &str = "bcrt1pfeesnyr2tx";

#[derive(Clone, Debug, PartialEq)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WithdrawalRequest {
    pub address: Address,
    pub amount: Amount,
}

pub fn create_main_transaction(
    previous_main_utxo: &Utxo,
    main_address: &Address,
    withdrawal_requests: Vec<WithdrawalRequest>,
    fee: Amount,
) -> Transaction {
    let main_input = TxIn {
        previous_output: previous_main_utxo.outpoint,
        script_sig: script::ScriptBuf::new(),
        sequence: transaction::Sequence::MAX,
        witness: Witness::default(),
    };
    let inputs = vec![main_input];

    let input_amount = previous_main_utxo.amount;
    let withdrawals_amount = withdrawal_requests.iter().map(|r| r.amount).sum::<Amount>();
    let change = input_amount - withdrawals_amount - fee;

    let mut outputs = vec![];

    // Main output is always at position 0
    outputs.push(TxOut {
        value: change,
        script_pubkey: main_address.script_pubkey(),
    });

    let anchor_script = Address::from_str(ANCHOR_ADDRESS)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();

    // Anchor output is always at position 1
    outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: anchor_script,
    });

    for withdrawal_request in withdrawal_requests {
        outputs.push(TxOut {
            value: withdrawal_request.amount,
            script_pubkey: withdrawal_request.address.script_pubkey(),
        });
    }

    Transaction {
        version: transaction::Version::non_standard(3),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

pub fn broadcast_transaction_package(
    rpc: &Client,
    transactions: Vec<&Transaction>,
) -> Result<Value, Error> {
    let txs_hex: Vec<String> = transactions.iter().map(|&tx| RawTx::raw_hex(tx)).collect();
    let txs_json: Value = json!(txs_hex);
    rpc.call("submitpackage", &[txs_json])
}

pub fn broadcast_transaction(rpc: &Client, transaction: &Transaction) -> Result<Txid, Error> {
    rpc.send_raw_transaction(transaction)
}

pub fn create_fee_sponsoring_transaction(
    anchor_utxo: &Utxo,
    fee_sponsor_utxo: &Utxo,
    fee_sponsor_address: &Address,
    fee: Amount,
) -> Transaction {
    let anchor_input = TxIn {
        previous_output: anchor_utxo.outpoint,
        script_sig: script::ScriptBuf::new(),
        sequence: transaction::Sequence::MAX,
        witness: Witness::default(),
    };

    let fee_sponsor_input = TxIn {
        previous_output: fee_sponsor_utxo.outpoint,
        script_sig: script::ScriptBuf::new(),
        sequence: transaction::Sequence::MAX,
        witness: Witness::default(),
    };
    let inputs = vec![anchor_input, fee_sponsor_input];

    let change = fee_sponsor_utxo.amount - fee;

    // Change going back to the fee sponsor
    let output = TxOut {
        value: change,
        script_pubkey: fee_sponsor_address.script_pubkey(),
    };
    let outputs = vec![output];

    Transaction {
        version: transaction::Version::non_standard(3),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

pub fn sign_input(
    tx: &Transaction,
    input_index: usize,
    value: Amount,
    script_pubkey: &ScriptBuf,
    private_key: &PrivateKey,
) -> Transaction {
    let secp = Secp256k1::new();
    let mut tx = tx.clone();

    let mut cache = SighashCache::new(&tx);

    let sighash = cache
        .p2wpkh_signature_hash(input_index, script_pubkey, value, EcdsaSighashType::All)
        .expect("sighash");

    let msg = Message::from_digest_slice(&sighash[..]).expect("Failed to create message");
    let sig = secp.sign_ecdsa(&msg, &private_key.inner);

    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);

    tx.input[input_index].witness.push(sig_bytes);
    tx.input[input_index]
        .witness
        .push(private_key.public_key(&secp).to_bytes());

    tx
}

pub fn sign_fee_sponsoring_transaction(
    tx: &Transaction,
    fee_sponsor_utxo: &Utxo,
    fee_sponsor_address: &Address,
    fee_sponsor_private_key: &PrivateKey,
) -> Transaction {
    sign_input(
        tx,
        1,
        fee_sponsor_utxo.amount,
        &fee_sponsor_address.script_pubkey(),
        &fee_sponsor_private_key,
    )
}

pub fn sign_main_transaction(
    tx: &Transaction,
    previous_main_utxo: &Utxo,
    main_address: &Address,
    private_key: &PrivateKey,
) -> Transaction {
    sign_input(
        tx,
        0,
        previous_main_utxo.amount,
        &main_address.script_pubkey(),
        private_key,
    )
}

pub fn create_and_sign_main_transaction_and_fee_transaction(
    main_utxo: &Utxo,
    main_address: &Address,
    main_private_key: &PrivateKey,
    fee_sponsor_utxo: &Utxo,
    fee_sponsor_address: &Address,
    fee_sponsor_private_key: &PrivateKey,
    withdrawal_requests: Vec<WithdrawalRequest>,
    fee: Amount,
) -> (Transaction, Utxo, Transaction, Utxo, Vec<Utxo>) {
    let main_tx =
        create_main_transaction(&main_utxo, &main_address, withdrawal_requests, Amount::ZERO);
    // println!("main_tx: {:?}", main_tx);
    let signed_main_tx =
        sign_main_transaction(&main_tx, &main_utxo, &main_address, &main_private_key);

    let next_main_utxo = Utxo {
        outpoint: OutPoint::new(main_tx.compute_txid(), 0), // main output at position 0
        amount: main_tx.output[0].value,
    };

    let anchor_utxo = Utxo {
        outpoint: OutPoint::new(main_tx.compute_txid(), 1), // anchor output at position 1
        amount: main_tx.output[1].value,
    };

    let fee_sponsoring_tx = create_fee_sponsoring_transaction(
        &anchor_utxo,
        &fee_sponsor_utxo,
        &fee_sponsor_address,
        fee,
    );

    let signed_fee_sponsoring_tx = sign_fee_sponsoring_transaction(
        &fee_sponsoring_tx,
        &fee_sponsor_utxo,
        &fee_sponsor_address,
        &fee_sponsor_private_key,
    );

    let next_fee_sponsor_utxo = Utxo {
        outpoint: OutPoint::new(signed_fee_sponsoring_tx.compute_txid(), 0), // only output is the change
        amount: signed_fee_sponsoring_tx.output[0].value,
    };

    let mut withdrawal_utxos = vec![];

    for withdrawal_id in 2..main_tx.output.len() {
        withdrawal_utxos.push(Utxo {
            outpoint: OutPoint::new(main_tx.compute_txid(), withdrawal_id as u32),
            amount: main_tx.output[withdrawal_id].value,
        });
    }

    (
        signed_main_tx,
        next_main_utxo,
        signed_fee_sponsoring_tx,
        next_fee_sponsor_utxo,
        withdrawal_utxos,
    )
}

pub fn create_withdrawal_spend_transaction(
    withdrawal_utxo: &Utxo,
    withdrawal_address: &Address,
    fee: Amount,
) -> Transaction {
    let withdrawal_input = TxIn {
        previous_output: withdrawal_utxo.outpoint,
        script_sig: script::ScriptBuf::new(),
        sequence: transaction::Sequence::MAX,
        witness: Witness::default(),
    };
    let inputs = vec![withdrawal_input];

    let change = withdrawal_utxo.amount - fee;

    let output = TxOut {
        value: change,
        script_pubkey: withdrawal_address.script_pubkey(),
    };
    let outputs = vec![output];

    Transaction {
        version: transaction::Version::non_standard(3),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

pub fn create_and_sign_withdrawal_spend_transaction(
    withdrawal_utxo: &Utxo,
    withdrawal_address: &Address,
    fee: Amount,
    withdrawal_private_key: &PrivateKey,
) -> Transaction {
    let tx = create_withdrawal_spend_transaction(withdrawal_utxo, withdrawal_address, fee);
    sign_input(
        &tx,
        0,
        withdrawal_utxo.amount,
        &withdrawal_address.script_pubkey(),
        &withdrawal_private_key,
    )
}
