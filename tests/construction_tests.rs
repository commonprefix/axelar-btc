use axelar_btc::transactions::{
    broadcast_transaction, broadcast_transaction_package,
    create_and_sign_main_transaction_and_fee_transaction,
    create_and_sign_withdrawal_spend_transaction, WithdrawalRequest,
};
use bitcoin::Amount;
use bitcoincore_rpc::RpcApi;

mod utils;

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
