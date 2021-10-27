// Need to generate a random key
// that can be authenticated with the data we have

pub use crate::crypto::context::{Operations};
use optee_utee::trace_println;
use optee_utee::{AlgorithmId, DeriveKey};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};

use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, KEY_SIZE};

/// Ta function generating DH key pair
pub fn generate_key(dh: &mut Operations, params: &mut Parameters) -> Result<()> {
//     Call p0-p3 from host
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_value().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    let mut p3 = unsafe { params.3.as_memref().unwrap() };
//     convert vector to bytes value
    let prime_base = p0.buffer();
    let prime_slice = &prime_base[..KEY_SIZE/8];
    let base_slice = &prime_base[KEY_SIZE/8..];
    trace_println!("{:?}", &base_slice);

    let attr_prime = AttributeMemref::from_ref(AttributeId::DhPrime, prime_slice);
    let attr_base = AttributeMemref::from_ref(AttributeId::DhBase, base_slice);

//     Generate key pair
    dh.dh_key = TransientObject::allocate(TransientObjectType::DhKeypair, KEY_SIZE).unwrap();
    // convert output vectors to bytes`
    let mut public_buffer = p2.buffer();
    let mut private_buffer = p3.buffer();

    dh.dh_key
        .generate_key(KEY_SIZE, &[attr_prime.into(), attr_base.into()])?;
    let mut key_size = dh
        .dh_key
        .ref_attribute(AttributeId::DhPublicValue, &mut public_buffer)
        .unwrap();
    p1.set_a(key_size as u32);
    key_size = dh
        .dh_key
        .ref_attribute(AttributeId::DhPrivateValue, &mut private_buffer)
        .unwrap();
    p1.set_b(key_size as u32);
    Ok(())
}