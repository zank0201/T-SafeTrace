// Need to generate a random key
// that can be authenticated with the data we have

pub use crate::crypto::context::*;
use optee_utee::trace_println;
use optee_utee::{AlgorithmId, DeriveKey};
use optee_utee::{AttributeId, AttributeValue, AttributeMemref, ElementId, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, KEY_SIZE};
use crate::storage::{data::*, trusted_keys::*};
use std::sync::{Arc, Mutex};
use std::collections::BTreeMap;
use rustc_hex::{FromHex, ToHex};
// use rustc_hex::{FromHex, ToHex};
lazy_static! { pub static ref DH_KEYS: Mutex<BTreeMap<PubKey, DHKey>> = Mutex::new(BTreeMap::new()); }

//
// pub fn ecdh_keypairs(key: &mut Operations) -> Result<()> {
//     trace_println!("allocate transient object to ecdh keypair");
//     key.ecdh_keypair = TransientObject::allocate(TransientObjectType::EcdhKeypair, KEY_SIZE).unwrap();
//     let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);
//     trace_println!("Generate out keypair");
//     key.ecdh_keypair
//         .generate_key(KEY_SIZE, &[attr_ecc.into()])?;
//     trace_println!("Done generating");
//     Ok(())
// }
// lazy_static! {pub static ref DH_KEYS: HashMap<Vec<u8>, DHKey> =  HashMap::new();}

pub fn generate_key(user_pub: &[u8], private_value: &[u8]) -> Result<()> {
    // let mut p0 = unsafe{params.0.as_value().unwrap()};
    // let mut p1 = unsafe{params.1.as_memref().unwrap()};
    // // ecc_public
    // let mut p2 = unsafe{params.2.as_memref().unwrap()};
    // ecc y
    // let mut p3 = unsafe{params.3.as_memref().unwrap()};
    let mut new_array = user_pub;

    let mut ecc_x = [0u8;32];
    let mut ecc_y = [0u8;32];
    ecc_x.clone_from_slice(&new_array[..32]);

    ecc_y.clone_from_slice(&new_array[32..]);


    let publicX_att = AttributeMemref::from_ref(AttributeId::EccPublicValueX, &ecc_x);
    let publicY_att = AttributeMemref::from_ref(AttributeId::EccPublicValueY, &ecc_y);
    trace_println!("allocate object");
    //call private key from struct

    let private_value = AttributeMemref::from_ref(AttributeId::EccPrivateValue, &private_value);
    trace_println!("curve att");
    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);
    let mut derived_buffer = [0u8;65];
    trace_println!("derive key function");

    match DeriveKey::allocate(AlgorithmId::EcdhDeriveSharedSecret, KEY_SIZE) {
        Err(e) => Err(e),
        Ok(operation) => {

            trace_println!("set key for ecdsa");
            // operation.set_key(&dh.ecdh_keypair)?;
            trace_println!("Allocate Generic secret");
            let mut dh_keypair = TransientObject::allocate(TransientObjectType::EcdhKeypair, KEY_SIZE).unwrap();
            trace_println!("populate keys");
            dh_keypair
                .populate(&[attr_ecc.into(), publicX_att.into(), publicY_att.into(), private_value.into()]);
            trace_println!("setKey");
            operation.set_key(&dh_keypair)?;

            trace_println!("derive keys operation");
            let mut derived_key =
            TransientObject::allocate(TransientObjectType::GenericSecret, KEY_SIZE).unwrap();


            trace_println!("derive key");
            operation.derive(&[publicX_att.into(), publicY_att.into()], &mut derived_key);
            let mut key_size = derived_key
                .ref_attribute(AttributeId::SecretValue, &mut derived_buffer)
                .unwrap();
            let mut derived_res = vec![0u8; key_size as usize];
            derived_res.copy_from_slice(&derived_buffer[..key_size as usize]);

            let derived_val = derived_array(&derived_res);
            trace_println!("derived_val {:?}", &derived_val);
            let pub_array = user_pub.to_hex();
            // trace_println!("io string {:?}", &user_string);
            DH_KEYS.lock_expect("DH_KEYS").insert(PubKey(pub_array.into()), derived_val);

            // map.insert_keys(String::from_utf8(derived_res), new_array, derived_res);



            trace_println!("done deriving");
            Ok(())
        }
    }

}
