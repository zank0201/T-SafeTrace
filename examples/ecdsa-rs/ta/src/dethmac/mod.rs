#![allow(unused)]
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};

use optee_utee::{AlgorithmId, Asymmetric,OperationMode, AttributeId, AttributeMemref, AttributeValue, Random, AE};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{TransientObject, TransientObjectType, ElementId};
use proto::{Command, Mode, BUFFER_SIZE, KEY_SIZE, TAG_LEN};


pub mod nistp256;
use crate::dethmac::nistp256::{Ecdsa, SecretKeys};
use ecdsa::rfc6979::generate_k;
use sha2::{Digest, Sha256};
pub use {
    p256::{AffinePoint, ProjectivePoint, Scalar},
    core::borrow::Borrow,
    ecdsa::hazmat::{SignPrimitive, VerifyPrimitive},
    elliptic_curve::{generic_array::GenericArray,
        dev::NonZeroScalar,
        group::ff::{Field,PrimeField},
        ops::{Invert},
    },
};

/// function generating ecdsa keypairs
/// returns scalar type of values
pub fn generate_key(ecdsa: &mut Ecdsa, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    trace_println!("allocating object mememory");
    // #[cfg(feature = "non-optee")]

    trace_println!("we are going to keypair");
    // SecretKey::random(CryptoRng + RngCore);
    ecdsa.key = TransientObject::allocate(TransientObjectType::EcdsaKeypair, KEY_SIZE).unwrap();
    // generate key pair

    /// generating key pair for edcsa requires the the domain Parameters
    /// ecc curve attribute
    /// generates attr of ecc gy and gx
    /// and private value
    /// get attribute using ECC curve attribute

    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);
    //generate key
    ecdsa.key
        .generate_key(KEY_SIZE, &[attr_ecc.into()])?;
    // init array of public and private keys generated
    let mut private_buffer = p0.buffer();
    let mut public_x_buffer = p1.buffer();
    let mut public_y_buffer = p2.buffer();
    trace_println!("set private key attribute");

    let mut private_key_size = ecdsa
        .key
        .ref_attribute(AttributeId::EccPrivateValue, &mut private_buffer)
        .unwrap();
    // using ref_attribute keeps value of buffer
    // what then needs to be done is to copy it from slice

    let mut private_res = vec![0u8; private_key_size as usize];

    private_res.copy_from_slice(&private_buffer[..private_key_size as usize]);

    let mut publicx_key_size = ecdsa
        .key
        .ref_attribute(AttributeId::EccPublicValueX, &mut public_x_buffer)
        .unwrap();

    let mut public_x_res = vec![0u8; publicx_key_size as usize];

    public_x_res.copy_from_slice(&public_x_buffer[..publicx_key_size as usize]);

    let mut publicy_key_size = ecdsa
        .key
        .ref_attribute(AttributeId::EccPublicValueY, &mut public_y_buffer)
        .unwrap();

    let mut public_y_res = vec![0u8; publicy_key_size as usize];

    public_y_res.copy_from_slice(&public_y_buffer[..publicy_key_size as usize]);

    // convert keypairs to scalar using elliptic curve scalar
    let private_scalar =  Scalar::from_repr(GenericArray::clone_from_slice(&private_res)).unwrap();
    let public_x_scalar =  Scalar::from_repr(GenericArray::clone_from_slice(&public_x_res)).unwrap();
    let public_y_scalar =  Scalar::from_repr(GenericArray::clone_from_slice(&public_y_res)).unwrap();
    // assign new key pair values to struct
    let SecretKeys {
    privatekey: private_scalar,
        public_y: public_y_scalar,
        public_x: public_x_scalar,
    };


    Ok(())
}
fn hmac_generate_k (private: &mut SecretKeys) -> Result<()> {
    let x = NonZeroScalar::from_repr(private.privatekey
        .into(),
    )
    .unwrap();

    let digest = Sha256::new().chain("sample");
    let k = generate_k(&x, digest, &[]);
    Ok(())
}
