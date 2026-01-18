use secp256k1::{
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
    hashes::{Hash, sha256},
    schnorr::Signature,
};
use sha2::Sha256;

pub fn sign_schnorr(privkey: &SecretKey, message: &[u8]) -> Signature {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, privkey);
    let hash = sha256::Hash::hash(&message);
    //let msg = Message::from_digest_slice(hash.as_ref()).unwrap();
    secp.sign_schnorr(hash.as_ref(), &keypair)
}

pub fn verify_schnorr(pubkey: &XOnlyPublicKey, message: &[u8], sig: &Signature) -> bool {
    let secp = Secp256k1::new();
    let hash = sha256::Hash::hash(&message);
    let msg = Message::from_digest_slice(hash.as_ref()).unwrap();
    secp.verify_schnorr(sig, &hash.as_ref(), pubkey).is_ok()
}
