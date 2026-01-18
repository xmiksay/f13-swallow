//mod derivation;
//mod master;
//mod signing;

//pub use derivation::{derive_private, derive_public};
//pub use master::MasterKey;
//pub use signing::{sign_schnorr, verify_schnorr};

use std::io::Read;

use hmac::{Hmac, Mac};
use secp256k1::{
    Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
    hashes::{Hash, sha256},
    rand::{Rng, rngs::OsRng},
    schnorr::Signature,
};
use sha2::{Sha256, Sha512};

pub struct MasterKey {
    pub privkey: SecretKey,
    pub pubkey: PublicKey,
}

impl MasterKey {
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::rng();
        let (privkey, pubkey) = secp.generate_keypair(&mut rng);

        MasterKey { privkey, pubkey }
    }
}

type HmacSha512 = Hmac<Sha512>;

pub fn derive_private(master_priv: &SecretKey, master_pub: &PublicKey, info: &[u8]) -> SecretKey {
    let mut mac = HmacSha512::new_from_slice(&master_pub.serialize()).unwrap();
    mac.update(info);
    let result = mac.finalize().into_bytes();

    let derived = master_priv.clone();
    let scalar = Scalar::from_le_bytes(result[..32].try_into().unwrap()).unwrap();
    derived.add_tweak(&scalar).unwrap()
}

pub fn derive_public(master_pub: &PublicKey, info: &[u8]) -> PublicKey {
    let mut mac = HmacSha512::new_from_slice(&master_pub.serialize()).unwrap();
    mac.update(info);
    let result = mac.finalize().into_bytes();

    let scalar = Scalar::from_le_bytes(result[..32].try_into().unwrap()).unwrap();
    let secp = Secp256k1::new();
    master_pub.add_exp_tweak(&secp, &scalar).unwrap()
}

pub fn sign_schnorr(privkey: &SecretKey, nonce: &[u8], message: &[u8]) -> Signature {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, privkey);

    let msg: Vec<u8> = nonce.iter().chain(message.iter()).cloned().collect();

    secp.sign_schnorr(&msg, &keypair)
}

pub fn verify_schnorr(
    pubkey: &XOnlyPublicKey,
    nonce: &[u8],
    message: &[u8],
    sig: &Signature,
) -> bool {
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
    let msg: Vec<u8> = nonce.iter().chain(message.iter()).cloned().collect();
    secp.verify_schnorr(sig, &msg, pubkey).is_ok()
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::MasterKey;
    use rust_decimal::Decimal;
    use secp256k1::schnorr::Signature;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Position {
        pub latitude: Decimal,
        pub longitude: Decimal,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub enum Message {
        Position(Position),
        Register(Vec<u8>),
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Envelope {
        // Random chars
        pub nonce: Vec<u8>,
        // Device identification
        pub id: Vec<u8>,
        // Message to send
        pub message: Message,
        // sign
        pub sign: Vec<u8>,
    }

    #[test]
    fn test_sign() {
        // Random generated key pair
        let master = MasterKey::generate();
        // Create message with data
        let mut data = Envelope {
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 10],
            id: vec![1, 2, 3, 4, 5, 6],
            message: Message::Position(Position {
                latitude: Decimal::from_str("2.1").unwrap(),
                longitude: Decimal::from_str("3.3").unwrap(),
            }),
            // Sign is empty
            sign: Vec::new(),
        };

        // Derive private key from master
        let private = super::derive_private(&master.privkey, &master.pubkey, &data.id);
        // Derive public key from master
        let public = super::derive_public(&master.pubkey, &data.id);
        // Transform message to bytes
        let msg = serde_json::to_vec(&data.message).unwrap();
        // Generate sign of message
        data.sign = super::sign_schnorr(&private, &data.nonce, &msg)
            .to_byte_array()
            .to_vec();

        // Verify that sign of message fits
        assert!(super::verify_schnorr(
            &public.x_only_public_key().0,
            &data.nonce,
            &msg,
            &Signature::from_byte_array(data.sign.try_into().unwrap())
        ))
    }
}
