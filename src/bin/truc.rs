use std::fs;
use std::path::Path;
use std::str::FromStr;

use axelar_btc::transactions::{create_and_sign_main_transaction_and_fee_transaction, Utxo};
use bitcoin::{
    key::Secp256k1,
    secp256k1::SecretKey,
    Address, Amount, CompressedPublicKey, Network, NetworkKind, OutPoint, PrivateKey, Txid,
};
use bitcoincore_rpc::RawTx;
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct KeysConfig {
    main_secret_key: String,
    fee_sponsor_secret_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct UtxoConfig {
    txid: String,
    vout: u32,
    amount_sats: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct UtxosConfig {
    main: UtxoConfig,
    fee_sponsor: UtxoConfig,
}

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    keys: KeysConfig,
    utxos: UtxosConfig,
}

fn load_config(network: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_path = format!("config/{}.toml", network);

    if !Path::new(&config_path).exists() {
        return Err(format!("Configuration file not found: {}", config_path).into());
    }

    let config_content = fs::read_to_string(config_path)?;
    let config: Config = toml::from_str(&config_content)?;
    Ok(config)
}

fn derive_address(priv_key: &PrivateKey, network: Network) -> Address {
    let secp = Secp256k1::new();
    let pub_key = CompressedPublicKey::from_private_key(&secp, priv_key).unwrap();

    Address::p2wpkh(&pub_key, network)
}

fn key_init(secret_key: SecretKey, network: Network) -> (PrivateKey, Address) {
    let network_kind = match network {
        Network::Bitcoin => NetworkKind::Main,
        Network::Testnet => NetworkKind::Test,
        Network::Signet => NetworkKind::Test,
        Network::Regtest => NetworkKind::Test,
        _ => NetworkKind::Test,
    };

    let private_key = PrivateKey {
        compressed: true,
        network: network_kind,
        inner: secret_key,
    };
    let address = derive_address(&private_key, network);
    (private_key, address)
}

fn utxo_config_to_utxo(utxo_config: &UtxoConfig) -> Result<Utxo, Box<dyn std::error::Error>> {
    let txid = Txid::from_str(&utxo_config.txid)?;
    let outpoint = OutPoint::new(txid, utxo_config.vout);
    let amount = Amount::from_sat(utxo_config.amount_sats);

    Ok(Utxo { outpoint, amount })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("truc")
        .version("1.0")
        .about("Bitcoin TRUC transaction creator")
        .arg(
            Arg::new("network")
                .long("network")
                .value_name("NETWORK")
                .help("Network to use: testnet4, signet, or mainnet")
                .value_parser(["testnet4", "signet", "mainnet"])
                .required(true)
        )
        .arg(
            Arg::new("fee")
                .long("fee")
                .value_name("SATS")
                .help("Transaction fee in satoshis")
                .value_parser(clap::value_parser!(u64))
                .required(true)
        )
        .get_matches();

    let network_str = matches.get_one::<String>("network").unwrap();
    let fee_sats = *matches.get_one::<u64>("fee").unwrap();

    // Load configuration from file
    let config = match load_config(network_str) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error loading configuration for {}: {}", network_str, e);
            eprintln!("Make sure the configuration file config/{}.toml exists", network_str);
            std::process::exit(1);
        }
    };

    let network = match network_str.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet4" => Network::Testnet,
        "signet" => Network::Signet,
        _ => {
            eprintln!("Invalid network: {}. Use 'testnet4', 'signet' or 'mainnet'", network_str);
            std::process::exit(1);
        }
    };

    println!("Using network: {}", network_str);

    // Parse secret keys from configuration
    let main_secret_key = match SecretKey::from_str(&config.keys.main_secret_key) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error parsing main secret key: {}", e);
            std::process::exit(1);
        }
    };

    let fee_sponsor_secret_key = match SecretKey::from_str(&config.keys.fee_sponsor_secret_key) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error parsing fee sponsor secret key: {}", e);
            std::process::exit(1);
        }
    };

    let (main_private_key, main_address) = key_init(main_secret_key, network);
    println!("Main Address: {}", main_address);

    let (fee_sponsor_private_key, fee_sponsor_address) = key_init(fee_sponsor_secret_key, network);
    println!("Fee Sponsor Address: {}", fee_sponsor_address);

    // Parse UTXOs from configuration
    let main_utxo = match utxo_config_to_utxo(&config.utxos.main) {
        Ok(utxo) => utxo,
        Err(e) => {
            eprintln!("Error parsing main UTXO: {}", e);
            std::process::exit(1);
        }
    };

    let fee_sponsor_utxo = match utxo_config_to_utxo(&config.utxos.fee_sponsor) {
        Ok(utxo) => utxo,
        Err(e) => {
            eprintln!("Error parsing fee sponsor UTXO: {}", e);
            std::process::exit(1);
        }
    };

    println!("Main UTXO: {}:{}", main_utxo.outpoint.txid, main_utxo.outpoint.vout);
    println!("Fee Sponsor UTXO: {}:{}", fee_sponsor_utxo.outpoint.txid, fee_sponsor_utxo.outpoint.vout);

    let fee = Amount::from_sat(fee_sats);
    println!("Transaction fee: {} sats", fee.to_sat());

    let (signed_main_tx, _next_main_utxo, signed_fee_sponsoring_tx, _next_fee_sponsor_utxo, _withdrawal_utxos) =
        create_and_sign_main_transaction_and_fee_transaction(
            &main_utxo,
            &main_address,
            &main_private_key,
            &fee_sponsor_utxo,
            &fee_sponsor_address,
            &fee_sponsor_private_key,
            vec![],
            fee,
        );

    let hex_main_tx = RawTx::raw_hex(&signed_main_tx);
    let main_vsize = signed_main_tx.vsize();
    println!("\nMain Transaction:");
    println!("{}", hex_main_tx);
    println!("txid: {}", signed_main_tx.compute_txid());
    println!("vsize: {}", main_vsize);

    let hex_fee_sponsoring_tx = RawTx::raw_hex(&signed_fee_sponsoring_tx);
    let fee_sponsoring_vsize = signed_fee_sponsoring_tx.vsize();
    println!("\nFee Sponsoring Transaction:");
    println!("{}", hex_fee_sponsoring_tx);
    println!("txid: {}", signed_fee_sponsoring_tx.compute_txid());
    println!("vsize: {}", fee_sponsoring_vsize);

    let total_vsize = main_vsize + fee_sponsoring_vsize;
    println!("\nTotal package vsize: {}", total_vsize);

    let fee_rate = fee.to_sat() as f64 / total_vsize as f64;
    println!("Package fee rate: {:.2} sat/vbyte", fee_rate);

    Ok(())
}
