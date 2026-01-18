use secp256k1::{
    PublicKey, Secp256k1, SecretKey,
    rand::{Rng, rngs::OsRng},
};

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
