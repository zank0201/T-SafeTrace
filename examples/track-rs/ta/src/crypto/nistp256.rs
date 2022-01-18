use optee_utee::{
trace_println,
};

use optee_utee::{AlgorithmId, Asymmetric,OperationMode, ObjectHandle, AttributeId, AttributeMemref, AttributeValue, Random, AE};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{TransientObject, TransientObjectType, ElementId};
use proto::{Command, BUFFER_SIZE, KEY_SIZE, TAG_LEN};
use crate::storage::data::*;
pub use crate::crypto::context::{Operations, User, Geolocation};
// use ta_keygen::*;
use rustc_hex::{FromHex, ToHex};

/// function generating crypto keypairs
///
pub fn ecdsa_keypair(ecdsa: &mut Operations, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_value().unwrap() };
    //p1 = userid
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };

    let mut private_buffer = [0u8;32];
    let mut public_x_buffer = p1.buffer();
    let mut public_y_buffer = p2.buffer();
    trace_println!("allocating object mememory");
    // #[cfg(feature = "non-optee")]
    // ecdh_keypairs(ecdsa);
    trace_println!("we are going to keypair");
    // SecretKey::random(CryptoRng + RngCore);
    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);
    ecdsa.ecdsa_keypair = TransientObject::allocate(TransientObjectType::EcdsaKeypair, KEY_SIZE).unwrap();

    trace_println!("generate_key");

    ecdsa.ecdsa_keypair
        .generate_key(KEY_SIZE, &[attr_ecc.into()])?;

    trace_println!("private key implementation");
    let mut private_key_size = ecdsa.ecdsa_keypair
        .ref_attribute(AttributeId::EccPrivateValue, &mut private_buffer)
        .unwrap();
    let mut private_res = vec![0u8; private_key_size as usize];
    private_res.copy_from_slice(&private_buffer[..private_key_size as usize]);

    let mut eccx_size = ecdsa.ecdsa_keypair
        .ref_attribute(AttributeId::EccPublicValueX, &mut public_x_buffer)
        .unwrap();

    let mut public_x_res = vec![0u8; eccx_size as usize];
    //
    public_x_res.copy_from_slice(&public_x_buffer[..eccx_size as usize]);


    p0.set_a(eccx_size as u32);
    //
    let mut y_keysize = ecdsa.ecdsa_keypair
        .ref_attribute(AttributeId::EccPublicValueY, &mut public_y_buffer)
        .unwrap();
    p0.set_b(y_keysize as u32);
    let mut public_y_res = vec![0u8; y_keysize as usize];
    //
    public_y_res.copy_from_slice(&public_y_buffer[..y_keysize as usize]);

    // let mut new_data: User = User::default();
    // //e
    ecdsa.user_details.public_x =  public_x_res.clone();
    ecdsa.user_details.public_y = public_y_res.clone();
    ecdsa.user_details.private_key = private_res.clone();
    // public_x_res.append(&mut public_y_res);
    Ok(())




}


pub fn generate_sign(ecdsa: &mut Operations, params: &mut Parameters) -> Result<()> {
    // allocate signing operation
    let mut p0 = unsafe { params.0.as_value().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    let mut sign_buff = p1.buffer();
    let msg_digest = p2.buffer();
    let ecc_x = AttributeMemref::from_ref(AttributeId::EccPublicValueX, &ecdsa.user_details.public_x);
    let ecc_y = AttributeMemref::from_ref(AttributeId::EccPublicValueY, &ecdsa.user_details.public_y);
    let private_value = AttributeMemref::from_ref(AttributeId::EccPrivateValue, &ecdsa.user_details.private_key);
    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);

    trace_println!("allocating signing operation");

    match Asymmetric::allocate(AlgorithmId::EcdsaP256, OperationMode::Sign, KEY_SIZE) {
        Err(e) => Err(e),
        Ok(operation) => {
            match TransientObject::allocate(TransientObjectType::EcdsaKeypair, KEY_SIZE){
                Err(e) => Err(e),
                Ok(mut ecdsa_keypair) => {
                    trace_println!("enter ppopulate transient_object");
                    ecdsa_keypair
                        .populate(&[attr_ecc.into(), ecc_x.into(), ecc_y.into(), private_value.into()]);
                    operation.set_key(&ecdsa_keypair);
                    operation
                        .sign_digest(&[], &msg_digest, &mut sign_buff);
                    Ok(())

                }
            }


        }
    }





}

/// Function verifies signature
///
pub fn verify(ecdsa: &mut Operations, params: &mut Parameters) -> Result<()> {

    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut signature_buff = p0.buffer();
    let msg_digest = p1.buffer();

    trace_println!("Implement verify");
    ecdsa.ecdsa_op = Asymmetric::allocate(AlgorithmId::EcdsaP256, OperationMode::Verify, 256).unwrap();
    trace_println!("set key operation");
    ecdsa.ecdsa_op.set_key(&ecdsa.ecdsa_keypair)?;
    trace_println!("verify");
    // //TODO add verify to OTP verification
    ecdsa.ecdsa_op.
        verify_digest(&[], &msg_digest, &signature_buff);
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



