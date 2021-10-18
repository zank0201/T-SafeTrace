#![allow(unused)]
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};


#[cfg(feature = "p256")]
use {crate::p256::ecdsa::{Signature, VerifyingKey, SigningKey}};
// use p256::SecretKey;
use optee_utee::{Error, ErrorKind, Parameters, Result};
pub use rand_core::{CryptoRng, RngCore};



#[cfg(feature = "p256")]
#[derive(Clone)]
pub struct SecretKey(p256::SecretKey);

/// NIST P-256 public key.

#[derive(Clone)]
#[cfg(feature = "p256")]
pub struct PublicKey(p256::PublicKey);

#[derive(Clone)]
#[cfg(feature = "p256")]
pub struct Signature(p256::ecdsa::Signature);
/// NIST P-256 keypair.
#[derive(Clone)]
#[cfg(feature = "p256")]
pub struct Keypair {
    /// Public key of the keypair
    pub public: PublicKey,
    /// Secret key of the keypair
    pub secret: SecretKey,
}
#[cfg(feature = "p256")]
impl SecretKey {
    pub fn random(rng: impl CryptoRng + RngCore) -> Self{
        trace_println!("We are implementing secret key");
        SecretKey(p256::SecretKey::random(rng))

    }
}



// impl Keypair {
//     /// Generate a random `Keypair`.
//     ///
//     /// The implementation uses rejection sampling.
//     pub fn random(rng: OsRng) -> Self {
//         let secret = SecretKey(p256::SecretKey::random(rng));
//         let public = secret.public_key();
//         trace_println!("we are in keypair");
//         Keypair { public, secret }
//     }
// }
// pub fn generate_signature() -> Result<()> {
//     let signing_key = SigningKey::random(&mut OsRng);
//     let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//     let signature = signing_key.sign(&message);
//     trace_println!("our signature {:?}", &signature);
//     Ok(())
// }

// //     generate value of R
// //     let Base = GenePoint
// //     {genx: vec![0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
// //                 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
// //                 0xd8, 0x98, 0xc2, 0x96],
// //         geny: vec![0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
// //                    0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
// //                    0x37, 0xbf, 0x51, 0xf5]};
//
// //
//
// }