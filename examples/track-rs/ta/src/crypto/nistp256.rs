use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};

use optee_utee::{AlgorithmId, Asymmetric,OperationMode, AttributeId, AttributeMemref, AttributeValue, Random, AE};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{TransientObject, TransientObjectType, ElementId};
use proto::{Command, BUFFER_SIZE, KEY_SIZE, TAG_LEN};

pub use crate::crypto::context::{Operations};
use crate::ta_keygen::ecdh_keypairs;
/// function generating crypto keypairs
/// returns scalar type of values
pub fn ecdsa_keypair(ecdsa: &mut Operations, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_value().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    let mut p3 = unsafe { params.3.as_memref().unwrap() };
    trace_println!("allocating object mememory");
    // #[cfg(feature = "non-optee")]
    ecdh_keypairs(ecdsa);
    trace_println!("we are going to keypair");
    // SecretKey::random(CryptoRng + RngCore);
    ecdsa.ecdsa_keypair = TransientObject::allocate(TransientObjectType::EcdsaKeypair, KEY_SIZE).unwrap();
    // generate key pair
    /// generating key pair for edcsa requires the the domain Parameters
    /// ecc curve attribute
    /// generates attr of ecc gy and gx
    /// and private value
    /// get attribute using ECC curve attribute

    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);
    //generate key
    ecdsa.ecdsa_keypair
        .generate_key(KEY_SIZE, &[attr_ecc.into()])?;
    // init array of public and private keys generated
    let mut private_buffer = p1.buffer();
    let mut public_x_buffer = p2.buffer();
    let mut public_y_buffer = p3.buffer();
    trace_println!("set private key attribute");

    let mut private_key_size = ecdsa
        .ecdsa_keypair
        .ref_attribute(AttributeId::EccPrivateValue, &mut private_buffer)
        .unwrap();
    // using ref_attribute keeps value of buffer
    // what then needs to be done is to copy it from slice

    // let mut private_res = vec![0u8; private_key_size as usize];

    // private_res.copy_from_slice(&private_buffer[..private_key_size as usize]);

    let mut x_keysize = ecdsa
        .ecdsa_keypair
        .ref_attribute(AttributeId::EccPublicValueX, &mut public_x_buffer)
        .unwrap();
    //
    // let mut public_x_res = vec![0u8; publicx_key_size as usize];
    //
    // public_x_res.copy_from_slice(&public_x_buffer[..publicx_key_size as usize]);

    p0.set_a(x_keysize as u32);

    let mut y_keysize = ecdsa
        .ecdsa_keypair
        .ref_attribute(AttributeId::EccPublicValueY, &mut public_y_buffer)
        .unwrap();
    p0.set_b(y_keysize as u32);
    // let mut public_y_res = vec![0u8; publicy_key_size as usize];
    //
    // public_y_res.copy_from_slice(&public_y_buffer[..publicy_key_size as usize]);



    Ok(())
}
pub fn generate_sign(ecdsa: &mut Operations, params: &mut Parameters) -> Result<()> {
    // allocate signing operation
    let mut p0 = unsafe { params.0.as_value().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    let mut sign_buff = p1.buffer();
    let msg_digest = p2.buffer();
    trace_println!("allocating signing operation");
    ecdsa.ecdsa_op = Asymmetric::allocate(AlgorithmId::EcdsaP256, OperationMode::Sign, 256).unwrap();
    // setting ket for sign
    trace_println!("Setting key for signing");
    // using our key pair generated

    ecdsa.ecdsa_op.set_key(&ecdsa.ecdsa_keypair)?;

    trace_println!("generate signing key");
    ecdsa.ecdsa_op.
        sign_digest(&[], &msg_digest, &mut sign_buff);
    trace_println!("The generated signature {:?}", &sign_buff);

    trace_println!("Implement verify");
    ecdsa.ecdsa_op = Asymmetric::alloca te(AlgorithmId::EcdsaP256, OperationMode::Verify, 256).unwrap();
    trace_println!("set key operation");
    ecdsa.ecdsa_op.set_key(&ecdsa.ecdsa_keypair)?;
    trace_println!("verify");
    //TODO add verify to OTP verification
    ecdsa.ecdsa_op.
        verify_digest(&[], &msg_digest, &sign_buff);
    trace_println!("Successful verification");


    Ok(())
}

//digest
pub fn update(digest: &mut Operations, params: &mut Parameters) -> Result<()> {
    let mut p = unsafe { params.0.as_memref().unwrap() };
    let buffer = p.buffer();
    digest.digestop.update(buffer);
    Ok(())
}

pub fn do_final(digest: &mut Operations, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_value().unwrap() };
    let input = p0.buffer();
    let output = p1.buffer();
    match digest.digestop.do_final(input, output) {
        Err(e) => Err(e),
        Ok(hash_length) => {
            p2.set_a(hash_length as u32);
            Ok(())
        }
    }
}



