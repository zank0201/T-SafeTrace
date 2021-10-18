#![feature(restricted_std)]
#![no_main]

pub mod dethmac;
pub use crate::dethmac::*;

use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{AlgorithmId, Asymmetric,OperationMode, AttributeId, AttributeMemref, AttributeValue, Random, AE};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{TransientObject, TransientObjectType, ElementId};
use proto::{Command, Mode, BUFFER_SIZE, KEY_SIZE, TAG_LEN};
use rand_core::{CryptoRng, RngCore};
//
// //  struct of geneerator point from NIST
// #[derive(Debug, PartialEq)]
// pub struct GenePoint{
//     pub genx: Vec<u8>,
//     pub geny: Vec<u8>,
//
// }
// pub struct Kvalue {
//     pub random_k: Vec<u8>
//
// }
// pub const Generator_X: [u8; 32] = [
//     0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
//     0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
//     0xd8, 0x98, 0xc2, 0x96
// ];
// pub const Generator_Y: [u8; 32] = [
//     0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
//     0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
//     0x37, 0xbf, 0x51, 0xf5
// ];
pub struct Ecdsa {
    pub key: TransientObject,
    pub op: Asymmetric,


}

impl Default for Ecdsa {
    fn default() -> Self {
        Self {
            key: TransientObject::null_object(),
            op: Asymmetric::null(),

        }
    }
}



#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut Ecdsa) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut Ecdsa) {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}

#[ta_invoke_command]
fn invoke_command(sess_ctx: &mut Ecdsa, cmd_id: u32, _params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        // call function to generate random key

        // call prepare function using input data from host
        Command::GenKey => {
            return generate_key(sess_ctx, _params);
        }
        // Command::RandomK => {
        //     return random(_params, sess_ctx);
        // }
        // Command::Sign => {
        //     return generate_sign(sess_ctx, _params);
        // }
        _ => {
            return Err(Error::new(ErrorKind::BadParameters));
        }
    }
}
//
// fn random(k: &mut Kvalue) -> Result<()>{
//
//     // let mut p = unsafe { params.0.as_memref().unwrap()};
//     // let mut buf = vec![0; p.buffer().len() as usize];
//     // buf.copy_from_slice(p.buffer());
//     let mut res = vec![0u8; KEY_SIZE/8 as usize];
//     Random::generate(&mut  res);
//     k.random_k = res;
//
//     Ok(())
//
// }
/// Function to prepare edcsa and store on transisent object
/// save to struct

pub fn generate_key(ecdsa: &mut Ecdsa, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_value().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
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

    let mut private_buffer = p1.buffer();
    let mut key_size = ecdsa
        .key
        .ref_attribute(AttributeId::EccPrivateValue, &mut private_buffer)
        .unwrap();
    p0.set_a(key_size as u32);

    Ok(())
}


/// Signature generation steps
/// 1) calculate message; h=hash(msg)
/// 2) generate random number k [random_key]
/// 3) calculate random point; R = k * G and take its x-cordinate: r=R.x
/// 4) calculate signature proof: s = k^-1 * (h + r * privkey)(mod n)
/// 5) Return signature r,s

pub fn generate_sign(ecdsa: &mut Ecdsa, params: &mut Parameters) -> Result<()> {
    // allocate signing operation
    let mut p0 = unsafe { params.0.as_value().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let sign_buff = p1.buffer();
    trace_println!("allocating signing operation");
    ecdsa.op = Asymmetric::allocate(AlgorithmId::EcdsaP256, OperationMode::Sign, KEY_SIZE).unwrap();
    // setting ket for sign
    trace_println!("Setting key for signing");
    // using our key pair generated

    ecdsa.op.set_key(&ecdsa.key)?;
    //TODO check how ecdsa key generated and how we can use it on asymmetric function
    Ok(())
}



// Functions to test out signature generation

// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 = 32 * 1024;
const TA_STACK_SIZE: u32 = 2 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"Example of TA using asymmetric cipher.\0";
const EXT_PROP_VALUE_1: &[u8] = b"Acipher TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
