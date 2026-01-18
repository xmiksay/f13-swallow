use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

pub fn derive_private(master_priv: &SecretKey, info: &[u8]) -> SecretKey {
    let mut mac = HmacSha512::new_from_slice(&master_priv[..]).unwrap();
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

    // použij "tweak add" pro výpočet derived public key
    let secp = Secp256k1::new();
    let derived = master_pub.clone();
    let scalar = Scalar::from_le_bytes(result[..32].try_into().unwrap()).unwrap();
    derived.add_exp_tweak(&secp, &scalar).unwrap()
}
