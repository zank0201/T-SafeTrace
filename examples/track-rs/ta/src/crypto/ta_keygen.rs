// Need to generate a random key
// that can be authenticated with the data we have

pub use crate::crypto::context::{Operations};
use optee_utee::trace_println;
use optee_utee::{AlgorithmId, DeriveKey};
use optee_utee::{AttributeId, AttributeValue, AttributeMemref, ElementId, TransientObject, TransientObjectType};

use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, KEY_SIZE};
use crate::storage::data::*;
pub use crate::crypto::context::{User, Geolocation};
/// Ta function generating DH key pair

pub fn ecdh_keypairs(key: &mut Operations) -> Result<()> {
    trace_println!("allocate transient object to ecdh keypair");
    key.ecdh_keypair = TransientObject::allocate(TransientObjectType::EcdhKeypair, KEY_SIZE).unwrap();
    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);
    trace_println!("Generate out keypair");
    key.ecdh_keypair
        .generate_key(KEY_SIZE, &[attr_ecc.into()])?;
    trace_println!("Done generating");
    Ok(())
}
//TODO connect create object to function
// Link ecdh derive key with ecdsa
pub fn generate_key(dh: &mut Operations, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe{params.0.as_value().unwrap()};
    let mut p1 = unsafe{params.1.as_memref().unwrap()};
    // ecc x
    let mut p2 = unsafe{params.2.as_memref().unwrap()};
    // ecc y
    let mut p3 = unsafe{params.3.as_memref().unwrap()};

    let ecc_x = AttributeMemref::from_ref(AttributeId::EccPublicValueX, p2.buffer());
    let ecc_y = AttributeMemref::from_ref(AttributeId::EccPublicValueY, p3.buffer());
    trace_println!("allocate object");
    // let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);

    // match TransientObject::allocate(TransientObjectType::EcdsaKeypair, KEY_SIZE) {
    //     Err(e) => Err(e),
    //     Ok(keypair) => {
    //         keypair.generate_key(256, &[attr_ecc.into(), ecc_x.into(), ecc_y.into()])?;
    //     Ok(())
    //     }
    // }
    match DeriveKey::allocate(AlgorithmId::EcdhDeriveSharedSecret, KEY_SIZE) {
        Err(e) => Err(e),
        Ok(operation) => {
            trace_println!("set key for ecdsa");
            operation.set_key(&dh.ecdh_keypair)?;
            trace_println!("Allocate Generic secret");
            let mut derived_key =
            TransientObject::allocate(TransientObjectType::GenericSecret, KEY_SIZE).unwrap();
            trace_println!("derive keys operation");
            operation.derive(&[ecc_x.into(), ecc_y.into()], &mut derived_key);
            let key_size = derived_key
                .ref_attribute(AttributeId::SecretValue, p1.buffer())
                .unwrap();
            p0.set_a(key_size as u32);
            Ok(())
        }
    }

}