use optee_utee::{TransientObject, TransientObjectType, AE, AlgorithmId, ElementId, Asymmetric, Digest};


use serde_json::{Value, json};
use serde::{Deserialize, Serialize};
// use rmp_serde::{Deserializer, Serializer};
//

pub const SHA1_HASH_SIZE: usize = 20;
pub const MAX_KEY_SIZE: usize = 64;
pub const MIN_KEY_SIZE: usize = 10;
pub const DBC2_MODULO: u32 = 100000000;
// struct containing public key and secret key

pub struct Operations {
    pub ecdsa_keypair: TransientObject,
    pub ecdh_keypair: TransientObject,
    pub ecdsa_op: Asymmetric,
    pub digestop: Digest,
    //otp
    pub counter: [u8; 8],
    pub key: [u8; MAX_KEY_SIZE],
    pub dh_key: TransientObject,
    pub key_len: usize,
    pub AeOp: AE,


}

impl Default for Operations {
    fn default() -> Self {
        Self {
            ecdsa_keypair: TransientObject::null_object(),
            ecdh_keypair: TransientObject::null_object(),
            ecdsa_op: Asymmetric::null(),
            digestop: Digest::allocate(AlgorithmId::Sha256).unwrap(),
            // otp
            counter: [0u8; 8],
            key: [0u8; MAX_KEY_SIZE],
            dh_key: TransientObject::null_object(),
            key_len: 0,
            AeOp: AE::null(),

        }
    }
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    ecc_x: String,
    ecc_y: String,
    derived_key: String,

}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Geolocation {
    lat: f64,
    lng: f64,
    startTS: i32,
    endTS: i32,
    testResult: bool
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum Storage_Data{
    _add_new_user {#[serde(flatten)] user: User, location: Geolocation}
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", rename = "result")]
pub enum User_Results {

}