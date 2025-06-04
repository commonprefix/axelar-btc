use std::str::FromStr;

use bitcoin::{
    absolute::LockTime, key::Secp256k1, script, secp256k1::Message, sighash::SighashCache,
    transaction, Address, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey, ScriptBuf,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Client, Error, RawTx, RpcApi};
use serde_json::{json, Value};
use utils::{Utxo, WithdrawalRequest};

mod utils;

const ANCHOR_ADDRESS: &str = "bcrt1pfeesnyr2tx";

fn create_main_transaction(
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

fn broadcast_transaction_package(
    rpc: &Client,
    transactions: Vec<&Transaction>,
) -> Result<Value, Error> {
    let txs_hex: Vec<String> = transactions.iter().map(|&tx| RawTx::raw_hex(tx)).collect();
    let txs_json: Value = json!(txs_hex);
    rpc.call("submitpackage", &[txs_json])
}

fn broadcast_transaction(rpc: &Client, transaction: &Transaction) -> Result<Txid, Error> {
    rpc.send_raw_transaction(transaction)
}

fn create_fee_sponsoring_transaction(
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

fn sign_input(
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

fn sign_fee_sponsoring_transaction(
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

fn sign_main_transaction(
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

fn create_and_sign_main_transaction_and_fee_transaction(
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

fn create_withdrawal_spend_transaction(
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

fn create_and_sign_withdrawal_spend_transaction(
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

#[test]
fn test_truc_transactions() {
    let (main_private_key, main_address) = utils::generate_key_pair();
    let (fee_sponsor_private_key, fee_sponsor_address) = utils::generate_key_pair();
    let rpc = utils::init_rpc();

    let [main_utxo, fee_sponsor_utxo] =
        utils::fund_addresses(&rpc, vec![&main_address, &fee_sponsor_address])
            .try_into()
            .unwrap();
    utils::mine_blocks(&rpc, 100); // Proceed 100 blocks in order for coinbase utxos to be spendable

    let (_, withdrawal_address) = utils::generate_key_pair();
    let withdrawal_request_1 = WithdrawalRequest {
        address: withdrawal_address.clone(),
        amount: Amount::from_btc(0.2).unwrap(),
    };

    let (withdrawal_private_key, withdrawal_address) = utils::generate_key_pair();
    let withdrawal_request_2 = WithdrawalRequest {
        address: withdrawal_address.clone(),
        amount: Amount::from_btc(0.3).unwrap(),
    };

    let (
        first_signed_main_tx,
        main_utxo,
        first_signed_fee_sponsoring_tx,
        fee_sponsor_utxo,
        withdrawal_utxos,
    ) = create_and_sign_main_transaction_and_fee_transaction(
        &main_utxo,
        &main_address,
        &main_private_key,
        &fee_sponsor_utxo,
        &fee_sponsor_address,
        &fee_sponsor_private_key,
        vec![withdrawal_request_1.clone(), withdrawal_request_2.clone()],
        Amount::from_sat(600),
    );

    // Main transaction alone should get rejected because it has zero fee
    assert!(broadcast_transaction(&rpc, &first_signed_main_tx).is_err());
    assert!(!rpc
        .get_raw_mempool()
        .unwrap()
        .contains(&first_signed_main_tx.compute_txid()));

    // Send fee sponsoring tx alone, should be rejected
    assert!(broadcast_transaction(&rpc, &first_signed_fee_sponsoring_tx).is_err());

    let signed_withdrawal_spend_tx = create_and_sign_withdrawal_spend_transaction(
        &withdrawal_utxos[1],
        &withdrawal_address,
        Amount::from_sat(600),
        &withdrawal_private_key,
    );
    // Send main tx with withdrawal spend tx as a 1P1C package that does not spend
    // the dust anchor utxo, should be rejected
    let package = broadcast_transaction_package(
        &rpc,
        vec![&first_signed_main_tx, &signed_withdrawal_spend_tx],
    )
    .unwrap();
    assert!(package
        .get("package_msg")
        .is_some_and(|v| v == "unspent-dust"));

    // Send main tx and fee sponsoring tx together as a 1P1C package
    // with order "child before parent", should be rejected
    assert!(broadcast_transaction_package(
        &rpc,
        vec![&first_signed_fee_sponsoring_tx, &first_signed_main_tx]
    )
    .is_err());

    // Send main tx and fee sponsoring tx together as a 1P1C package
    // with order "parent before child", should be accepted and
    // included in the mempool
    assert!(broadcast_transaction_package(
        &rpc,
        vec![&first_signed_main_tx, &first_signed_fee_sponsoring_tx]
    )
    .is_ok());
    assert!(rpc
        .get_raw_mempool()
        .unwrap()
        .contains(&first_signed_main_tx.compute_txid()));
    assert!(rpc
        .get_raw_mempool()
        .unwrap()
        .contains(&first_signed_main_tx.compute_txid()));

    let (second_signed_main_tx, _, second_signed_fee_sponsoring_tx, _, _) =
        create_and_sign_main_transaction_and_fee_transaction(
            &main_utxo,
            &main_address,
            &main_private_key,
            &fee_sponsor_utxo,
            &fee_sponsor_address,
            &fee_sponsor_private_key,
            vec![withdrawal_request_1.clone(), withdrawal_request_2.clone()],
            Amount::from_sat(600),
        );
    // Broadcast next main transaction alone before previous main transaction is confirmed, should be rejected
    assert!(broadcast_transaction(&rpc, &second_signed_main_tx).is_err());

    // Broadcast next main transaction as package with fee sponsoring transaction,
    // should be rejected and not replace any existing transactions in the mempool
    let package = broadcast_transaction_package(
        &rpc,
        vec![&second_signed_main_tx, &second_signed_fee_sponsoring_tx],
    )
    .unwrap();
    assert!(package
        .get("package_msg")
        .is_some_and(|v| v == "package-not-child-with-unconfirmed-parents"));
    assert!(package
        .get("replaced-transactions")
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!rpc
        .get_raw_mempool()
        .unwrap()
        .contains(&second_signed_main_tx.compute_txid()));
    assert!(!rpc
        .get_raw_mempool()
        .unwrap()
        .contains(&second_signed_fee_sponsoring_tx.compute_txid()));

    // Proceed to the next block
    let block_hash = utils::mine_blocks(&rpc, 1)[0];
    let block = rpc.get_block_info(&block_hash).unwrap();

    // Check that first main transaction and its fee sponsoring transaction are
    // included in the block
    assert!(block.tx.contains(&first_signed_main_tx.compute_txid()));
    assert!(block
        .tx
        .contains(&first_signed_fee_sponsoring_tx.compute_txid()));

    // Mempool should now be empty
    assert!(rpc.get_raw_mempool().unwrap().is_empty());

    // Broadcast next main transaction as package with fee sponsoring transaction.
    // Now that the previous main transaction is confirmed, it should be accepted.
    let package = broadcast_transaction_package(
        &rpc,
        vec![&second_signed_main_tx, &second_signed_fee_sponsoring_tx],
    )
    .unwrap();
    assert!(package.get("package_msg").is_some_and(|v| v == "success"));
    assert!(rpc
        .get_raw_mempool()
        .unwrap()
        .contains(&second_signed_main_tx.compute_txid()));
    assert!(rpc
        .get_raw_mempool()
        .unwrap()
        .contains(&second_signed_fee_sponsoring_tx.compute_txid()));
}
