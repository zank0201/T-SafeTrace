use optee_utee::{TransientObject, ObjectInfo, ObjectHandle, TransientObjectType, AE, AlgorithmId, ElementId, Asymmetric, Digest};
use std::collections::HashMap;

use derive_new::new;
use std::{marker, mem, ptr};

use serde_json::{Value, json};
use serde::{Deserialize, Serialize};
// use rmp_serde::{Deserializer, Serializer};
//
use rustc_hex::{FromHex, ToHex};
pub use proto::{KEY_SIZE};
pub type SymmetricKey = [u8; KEY_SIZE];
pub type DHKey = SymmetricKey;
pub const SHA1_HASH_SIZE: usize = 20;
pub const MAX_KEY_SIZE: usize = 64;
pub const MIN_KEY_SIZE: usize = 10;
pub const DBC2_MODULO: u32 = 100000000;
// struct containing public key and secret key

/// static ref keeping track of pubkey and derived key
/// #Parameters
/// Vec<u8>, = public key
/// DHKey = derived key
lazy_static! {
    pub static ref DHKeys: HashMap<Vec<u8>, DHKey> = HashMap::new();
}
pub struct Operations {
    pub ecdsa_keypair: TransientObject,
    pub ecdh_keypair: TransientObject,
    // pub ecdh_info: TransientObject,
    pub ecdsa_op: Asymmetric,
    pub digestop: Digest,
    //otp
    pub counter: [u8; 8],
    pub key: [u8; MAX_KEY_SIZE],
    pub dh_key: TransientObject,
    pub key_len: usize,
    pub AeOp: AE,
    pub user_details: User,


}

impl Default for Operations {
    fn default() -> Self {
        Self {
            ecdsa_keypair: TransientObject::null_object(),

            ecdh_keypair: TransientObject::null_object(),
            // ecdh_info,
            ecdsa_op: Asymmetric::null(),
            digestop: Digest::allocate(AlgorithmId::Sha256).unwrap(),
            // otp
            counter: [0u8; 8],
            key: [0u8; MAX_KEY_SIZE],
            dh_key: TransientObject::null_object(),
            key_len: 0,
            AeOp: AE::null(),
            user_details: User::default(),

        }
    }
}

///Struct [`User`] keeps Serialized data for user
#[derive(Default)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub public_x: Vec<u8>,
    pub public_y: Vec<u8>,
    // derived_key: String,
    pub private_key: Vec<u8>,
    //
    pub Geolocation_data: Geolocation,

}

#[derive(Serialize, Deserialize, Clone, Debug)]
// #[serde(tag = "type")]
pub struct Geolocation {
    lat: f64,
    lng: f64,
    startTS: i32,
    endTS: i32,
    testResult: bool
}
impl Default for Geolocation {
    fn default() -> Self {
        Self {
            lat: 0.0,
            lng: 0.0,
            startTS: 0,
            endTS: 0,
            testResult: false,
        }

        }

}
// pub struct Keypair {
//     pubkey: (String),
//     private_key: String,
// }
// impl Keypair {
//     pub fn hex_keypair(&mut self, ecc_x: Vec<u8>, ecc_y: Vec<u8>, private_key: Vec<u8>)
//     {
//         // let public_x = ecc_x.to_hex();
//         // let public_y = ecc_y.to_hex();
//         // let hex_private = private_key.to_hex();
//         let result = format!("{}\n{}", ecc_x.to_hex(), ecc_y.to_hex());
//         self.pubkey = (result);
//         self.private_key = private_key.to_hex();
//     }
//
//     // pub fn derive_public_pair(publickey: String) -> (Vec<u8>, Vec<u8>) {
//     //     let ecc_x,
//     // }
//
// }