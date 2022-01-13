use optee_utee::{TransientObject, ObjectInfo, ObjectHandle, TransientObjectType, AE, AlgorithmId, ElementId, Asymmetric, Digest};

use derive_new::new;
use std::{marker, mem, ptr};

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
// impl UserBuilder {
//     pub fn new(ecc_x: impl Into<String>, ecc_y: impl Into<String>, private_key: impl Into<String>) -> Self {
//         UserBuilder {
//             ecc_x: ecc_x.into(),
//             ecc_y: ecc_y.into(),
//             // derived_key: "",
//             private_key: private_key.into(),
//             Geolocation_data: None,
//
//         }
//     }
//     pub fn add_location(&mut self, Geolocation_data: Geolocation) -> Self {
//         self.Geolocation_data = Some(Geolocation_data);
//         self
//     }
//
//     pub fn build(self) -> UserBuilder {
//         let ecc_x = self.ecc_x;
//         let ecc_y = self.ecc_y;
//         let private_key = self.private_key;
//         let Geolocation_data = self.
//             Geolocation_data.expect("No data found");
//         UserBuilder {ecc_x, ecc_y, private_key, Geolocation_data}
//     }
// }

// pub struct User {
//     pub ecc_x: String,
//     pub ecc_y: String,
//     // derived_key: String,
//     pub private_key: String,
//     //
//     pub Geolocation_data: Geolocation,
//
// }
// impl User {
//     pub fn add_geolocation(&self) {
//         if let Some(ref Geolocation_data) = self.Geolocation_data
//     }
// }
// #[derive(Serialize, Deserialize, Debug, Clone)]
// #[serde(tag = "type")]
// pub enum Storage_Data{
//     _add_new_user {#[serde(flatten)] user: User, location: Geolocation}
// }
// #[derive(Serialize, Deserialize, Debug, Clone)]
// #[serde(rename_all = "camelCase", rename = "result")]
// pub enum User_Results {
//
// }