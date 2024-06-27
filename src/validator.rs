use bitcoin::{
    bip32::Xpriv,
    key::Secp256k1,
    secp256k1::{All, Message},
    taproot::Signature,
    TapSighash, TapSighashType, XOnlyPublicKey,
};
use bitcoin_hashes::Hash;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Validator {
    pub operator_address: String,
    // TODO: make sure this is the weight we should use
    #[serde(rename = "quadratic_voting_power")]
    pub weight: i64,
    #[serde(skip_deserializing)]
    pub key: Option<Xpriv>,
}

impl Validator {
    pub fn public_key(&self, secp: &Secp256k1<All>) -> XOnlyPublicKey {
        self.key.unwrap().to_keypair(&secp).x_only_public_key().0
    }

    // The validators blindly trust the signature hash that they need to sign,
    // and provide their Schnorr signatures on it.
    pub fn sign_sighash(&self, sighash: &TapSighash, secp: &Secp256k1<All>) -> Signature {
        let msg = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();

        Signature {
            signature: secp.sign_schnorr(&msg, &self.key.unwrap().to_keypair(&secp)),
            sighash_type: TapSighashType::Default,
        }
    }
}
