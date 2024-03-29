use optee_utee::{
trace_println,
};
use optee_utee::Time;
use optee_utee::{AlgorithmId, Asymmetric,OperationMode, ObjectHandle, AttributeId, AttributeMemref, AttributeValue, Random, AE};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{TransientObject, TransientObjectType, ElementId};
use proto::{Command, BUFFER_SIZE, KEY_SIZE, TAG_LEN};
use crate::storage::{data::*, trusted_keys::KeyStorage};
use crate::crypto::{ta_keygen::*, ta_hotp::*};
pub use crate::crypto::context::*;

/// function generating crypto keypairs
///@params:
/// p1 = publickey buffer
/// p2 = client pub key -> derived key
/// p3 signature buffer
///
//TODO save derived key and public key to storage

pub fn ecdsa_keypair(params: &mut Parameters) -> Result<()> {
    // trace_println!("Entered ecdsa");

    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    //p1 = userid
    let mut ecdsa = NewOperations::default();
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    let mut p3 = unsafe { params.3.as_memref().unwrap() };
    let mut private_buffer = [0u8;32];
    // let mut public_buffer = p1.buffer();
    let mut client_key = p2.buffer();
    let mut sign_buffer = p3.buffer();

    //
    // let (mut ecc_x_buffer, mut ecc_y_buffer) = public_buffer.split_at(public_buffer.len()/2);
    let mut ecc_x_buffer = p0.buffer();
    let mut ecc_y_buffer = p1.buffer();
    // let (mut user_pub, mut sign) = buffer.split_at_mut(buffer.len()/2);
    // ecc_x_buffer.clone_from_slice(&public_buffer[..32]);
    // ecc_y_buffer.clone_from_slice(&public_buffer[32..]);

    // #[cfg(feature = "non-optee")]
    // ecdh_keypairs(ecdsa);
    // SecretKey::random(CryptoRng + RngCore);
    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);


    ecdsa.ecdsa_keypair = TransientObject::allocate(TransientObjectType::EcdsaKeypair, KEY_SIZE).unwrap();




    ecdsa.ecdsa_keypair
        .generate_key(KEY_SIZE, &[attr_ecc.into()])?;

    let mut private_key_size = ecdsa.ecdsa_keypair
        .ref_attribute(AttributeId::EccPrivateValue, &mut private_buffer)
        .unwrap();
    let mut private_res = vec![0u8; private_key_size as usize];
    private_res.copy_from_slice(&private_buffer[..private_key_size as usize]);

    let mut eccx_size = ecdsa.ecdsa_keypair
        .ref_attribute(AttributeId::EccPublicValueX, &mut ecc_x_buffer)
        .unwrap();

    let mut public_x_res = vec![0u8; eccx_size as usize];
    //

    public_x_res.copy_from_slice(&ecc_x_buffer[..eccx_size as usize]);


    // p0.set_a(eccx_size as u32);
    //
    let mut y_keysize = ecdsa.ecdsa_keypair
        .ref_attribute(AttributeId::EccPublicValueY, &mut ecc_y_buffer)
        .unwrap();
    // p0.set_b(y_keysize as u32);
    let mut public_y_res = vec![0u8; y_keysize as usize];
    //
    public_y_res.copy_from_slice(&ecc_y_buffer[..y_keysize as usize]);

    // call derive key
    generate_key(&client_key, &private_res)?;
    // call generate sign

    let sig = generate_sign(&mut ecdsa, sign_buffer).unwrap();
    p3.buffer().copy_from_slice(&sig[..]);

    p0.buffer().copy_from_slice(&public_x_res);
    p1.buffer().copy_from_slice(&public_y_res);
    // let mut new_data: User = User::default();
    // //e

    //
    // ecdsa.public_x =  vector_array(&public_x_res);
    // ecdsa.public_y = vector_array(&public_y_res);
    // ecdsa.private_key = vector_array(&private_res);
    // // public_x_res.append(&mut public_y_res);
    // trace_println!("change values for struct {:?}", &ecdsa.private_key);
    //

    // trace_println!("delta_time {}", delta_time);
    Ok(())




}
const PREFIX: &'static [u8; 19] = b"Enigma User Message";


pub fn generate_sign(ecdsa: &mut NewOperations, sig: &mut [u8]) -> Result<Vec<u8>> {
    // allocate signing operation
    // trace_println!("entered signature");
    // let mut p0 = unsafe { params.0.as_value().unwrap() };
    // let mut p1 = unsafe { params.1.as_memref().unwrap() };
    // let mut p2 = unsafe { params.2.as_memref().unwrap() };
    // let mut sign_buff = p1.buffer();
    // let msg_digest = p2.buffer();
    //start hash
    let mut hash: [u8; 32] = [0u8; 32];
    update(ecdsa, &PREFIX[..]);
    let hash_length = do_final(ecdsa, &PREFIX[..], &mut hash).unwrap();
    let mut res = hash.to_vec();
    res.truncate(hash_length);

    // let ecc_x = AttributeMemref::from_ref(AttributeId::EccPublicValueX, &ecdsa.ecdsa_keypair);
    // let ecc_y = AttributeMemref::from_ref(AttributeId::EccPublicValueY, &ecdsa.ecdsa_keypair);
    // let private_value = AttributeMemref::from_ref(AttributeId::EccPrivateValue, &ecdsa.ecdsa_keypair);
    // let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);


    match Asymmetric::allocate(AlgorithmId::EcdsaP256, OperationMode::Sign, KEY_SIZE) {
        Err(e) => Err(e),
        Ok(operation) => {
            // match TransientObject::allocate(TransientObjectType::EcdsaKeypair, KEY_SIZE){
            //     Err(e) => Err(e),
            //     Ok(mut ecdsa_keypair) => {
            //         trace_println!("enter ppopulate transient_object");
            //         ecdsa_keypair
            //             .populate(&[attr_ecc.into(), ecc_x.into(), ecc_y.into(), private_value.into()]);
                    operation.set_key(&ecdsa.ecdsa_keypair);
                    operation
                        .sign_digest(&[], &res,  &mut *sig);

                    Ok(sig.to_vec())

                }



        }
    }







/// Function verifies signature
///
pub fn verify(sig: &mut [u8], user_pubkey: &mut [u8]) -> Result<()> {

    // allocate signing operation
    // let mut p0 = unsafe { params.0.as_value().unwrap() };
    // let mut p1 = unsafe { params.1.as_memref().unwrap() };
    // let mut p2 = unsafe { params.2.as_memref().unwrap() };
    // let mut sign_buff = p1.buffer();
    // let msg_digest = p2.buffer();
    //start hash
    let mut new_array = user_pubkey;

    let mut ecc_x = [0u8;32];
    let mut ecc_y = [0u8;32];
    ecc_x.clone_from_slice(&new_array[..32]);

    ecc_y.clone_from_slice(&new_array[32..]);

    let mut ecdsa = NewOperations::default();

    let publicX_att = AttributeMemref::from_ref(AttributeId::EccPublicValueX, &ecc_x);
    let publicY_att = AttributeMemref::from_ref(AttributeId::EccPublicValueY, &ecc_y);
    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);

    // let private_att = AttributeValue::from_value(AttributeId::EccPrivateValue, , );
    let mut hash: [u8; 32] = [0u8; 32];
    update(&mut ecdsa, &PREFIX[..]);
    let hash_length = do_final(&mut ecdsa, &PREFIX[..], &mut hash)?;
    let mut res = hash.to_vec();
    res.truncate(hash_length);

    // let ecc_x = AttributeMemref::from_ref(AttributeId::EccPublicValueX, &ecdsa.ecdsa_keypair);
    // let ecc_y = AttributeMemref::from_ref(AttributeId::EccPublicValueY, &ecdsa.ecdsa_keypair);
    // let private_value = AttributeMemref::from_ref(AttributeId::EccPrivateValue, &ecdsa.ecdsa_keypair);
    // let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);


    match Asymmetric::allocate(AlgorithmId::EcdsaP256, OperationMode::Verify, KEY_SIZE) {
        Err(e) => Err(e),
        Ok(operation) => {
            match TransientObject::allocate(TransientObjectType::EcdsaPublicKey, KEY_SIZE) {
                Err(e) => Err(e),
                Ok(mut ecdsa_keypair) => {
                    ecdsa_keypair.populate(&[attr_ecc.into(),
                        publicX_att.into(), publicY_att.into()]);

                //             .populate(&[attr_ecc.into(), ecc_x.into(), ecc_y.into(), private_value.into()]);
                operation.set_key(&ecdsa_keypair);
                operation
                .verify_digest(&[], &res, & mut *sig);
                    // trace_println!("Verified");
                Ok(())
            }
        }
    }

    }

}

//digest
pub fn update(digest: &mut NewOperations, msg_digest: &[u8]) -> Result<()> {
    // let mut p = unsafe { params.0.as_memref().unwrap() };
    // let buffer = p.buffer();
    digest.digestop.update(msg_digest);
    Ok(())
}

pub fn do_final(digest: &mut NewOperations, msg_digest: &[u8], output: &mut [u8]) -> Result<usize> {
    // let mut p0 = unsafe { params.0.as_memref().unwrap() };
    // let mut p1 = unsafe { params.1.as_memref().unwrap() };
    // let mut p2 = unsafe { params.2.as_value().unwrap() };
    // let input = p0.buffer();
    // let output = p1.buffer();
    match digest.digestop.do_final(msg_digest, output) {
        Err(e) => Err(e),
        Ok(hash_length) => {
            Ok(hash_length)
        }
    }
}



