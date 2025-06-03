use bitcoin::{
    absolute::LockTime, key::Secp256k1, script, secp256k1::Message, sighash::SighashCache,
    transaction, Address, Amount, EcdsaSighashType, OutPoint, PrivateKey, Transaction, TxIn, TxOut,
    Witness,
};
use bitcoincore_rpc::{Client, RpcApi};
use utils::{Utxo, WithdrawalRequest};

mod utils;

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

fn sign_main_transaction(
    tx: &Transaction,
    previous_main_utxo: &Utxo,
    main_address: &Address,
    private_key: &PrivateKey,
) -> Transaction {
    let secp = Secp256k1::new();
    let mut tx = tx.clone();

    let mut cache = SighashCache::new(&tx);

    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &main_address.script_pubkey(),
            previous_main_utxo.amount,
            EcdsaSighashType::All,
        )
        .expect("sighash");

    let msg = Message::from_digest_slice(&sighash[..]).expect("Failed to create message");
    let sig = secp.sign_ecdsa(&msg, &private_key.inner);

    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);

    tx.input[0].witness.push(sig_bytes);
    tx.input[0]
        .witness
        .push(private_key.public_key(&secp).to_bytes());

    tx
}

fn broadcast_transactions(rpc: &Client, transactions: &Vec<Transaction>) {
    for tx in transactions {
        match rpc.send_raw_transaction(tx) {
            Ok(txid) => println!("txid: {:?}", txid),
            Err(e) => println!("error: {:?}", e),
        }
    }
}

#[test]
fn test_truc_transactions() {
    let (private_key, main_address) = utils::generate_key_pair();
    let rpc = utils::init_rpc();

    let mut main_utxo = utils::fund_address(&rpc, &main_address);

    let (_, withdrawal_address) = utils::generate_key_pair();
    let withdrawal_request_1 = WithdrawalRequest {
        address: withdrawal_address,
        amount: Amount::from_btc(0.2).unwrap(),
    };

    let (_, withdrawal_address) = utils::generate_key_pair();
    let withdrawal_request_2 = WithdrawalRequest {
        address: withdrawal_address,
        amount: Amount::from_btc(0.3).unwrap(),
    };

    let mut signed_main_transactions = vec![];

    for _ in 0..3 {
        let main_tx = create_main_transaction(
            &main_utxo,
            &main_address,
            vec![withdrawal_request_1.clone(), withdrawal_request_2.clone()],
            Amount::from_sat(600),
        );

        let signed_tx = sign_main_transaction(&main_tx, &main_utxo, &main_address, &private_key);
        signed_main_transactions.push(signed_tx.clone());

        main_utxo = Utxo {
            outpoint: OutPoint::new(main_tx.compute_txid(), 0),
            amount: main_tx.output[0].value,
        };
    }

    broadcast_transactions(&rpc, &signed_main_transactions);

    let mempool = rpc.get_raw_mempool().unwrap();
    println!("mempool: {:?}", mempool);
    assert!(
        mempool.contains(&signed_main_transactions[0].compute_txid()),
        "Transaction not in mempool"
    );
    assert!(
        mempool.contains(&signed_main_transactions[1].compute_txid()),
        "Transaction not in mempool"
    );

    // Proceed to the next block
    rpc.generate_to_address(1, &main_address).unwrap();

    // Broadcast all the transactions again
    broadcast_transactions(&rpc, &signed_main_transactions);

    let mempool = rpc.get_raw_mempool().unwrap();
    println!("mempool: {:?}", mempool);
    assert!(
        mempool.contains(&signed_main_transactions[2].compute_txid()),
        "Transaction not in mempool"
    );
}
