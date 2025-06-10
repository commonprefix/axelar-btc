use std::path::PathBuf;

use axelar_btc::transactions::Utxo;
use bitcoin::{
    key::{rand, Secp256k1},
    secp256k1::SecretKey,
    Address, BlockHash, CompressedPublicKey, Network, NetworkKind, OutPoint, PrivateKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};

const COOKIE: &str = ".cookie";
const RPC_URL: &str = "http://127.0.0.1:18443";

pub fn init_rpc() -> Client {
    let bitcoin_dir = std::env::var("BITCOIN_DIR").unwrap();

    Client::new(
        RPC_URL,
        Auth::CookieFile(PathBuf::from(&(bitcoin_dir.to_owned() + COOKIE))),
    )
    .unwrap()
}

fn generate_private_key() -> PrivateKey {
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    PrivateKey {
        compressed: true,
        network: NetworkKind::Test,
        inner: secret_key,
    }
}

fn derive_address(priv_key: &PrivateKey) -> Address {
    let secp = Secp256k1::new();
    let pub_key = CompressedPublicKey::from_private_key(&secp, priv_key).unwrap();

    Address::p2wpkh(&pub_key, Network::Regtest)
}

pub fn generate_key_pair() -> (PrivateKey, Address) {
    let private_key = generate_private_key();
    let address = derive_address(&private_key);
    (private_key, address)
}

fn get_funding_utxo(rpc: &Client, block_hash: BlockHash) -> Utxo {
    let block = rpc.get_block_info(&block_hash).unwrap();
    let coinbase_txid = block.tx[0]; // Coinbase is always tx[0]

    let raw_tx = rpc
        .get_raw_transaction(&coinbase_txid, Some(&block_hash))
        .unwrap();
    let tx_decoded = rpc.decode_raw_transaction(&raw_tx, None).unwrap();

    let vout_index = 0;
    Utxo {
        outpoint: OutPoint::new(coinbase_txid, vout_index),
        amount: tx_decoded.vout[vout_index as usize].value,
    }
}

pub fn fund_address(rpc: &Client, address: &Address) -> Utxo {
    let block_hash = rpc.generate_to_address(1, &address).unwrap()[0];
    get_funding_utxo(rpc, block_hash)
}

pub fn fund_addresses(rpc: &Client, address: Vec<&Address>) -> Vec<Utxo> {
    let mut utxos = vec![];
    for addr in address {
        let utxo = fund_address(rpc, addr);
        utxos.push(utxo);
    }

    utxos
}

pub fn mine_blocks(rpc: &Client, count: u64) -> Vec<BlockHash> {
    let (_, address) = generate_key_pair();
    rpc.generate_to_address(count, &address).unwrap()
}
