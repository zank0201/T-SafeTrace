#![allow(unused_imports)]
#![allow(unused)]
use optee_teec::{
    Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid,
};
const PREFIX: &'static [u8; 19] = b"Enigma User Message";
// use hex::{FromHex, ToHex};

use std::str;
use rmp_serde::Deserializer;
use serde::Deserialize;
use serde_json::Value;
use proto::{Command,  AAD_LEN, BUFFER_SIZE, KEY_SIZE, UUID};


/// Function taking in edcsa paramaters for P-256
/// parameters:
/// 1) session
/// returns private key generated from ta
///
use rustc_hex::{FromHex, ToHex};
// type ResponseResult = Result<IpcResponse, Error>;
use failure::Error;
/// Function linked to [`generate_sign()`]
pub fn ecdsa_keypair(session: &mut Session, user_pubkey: &str) -> optee_teec::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {


    // output arrays to get private and public values
//public key x and y output buffer
    let mut publickey_x = [0u8;32];
    let mut publickey_y = [0u8;32];
    // client public key used for derived key
    let mut user_pub = &user_pubkey[2..].from_hex().unwrap();
    // let user_id = nanoid!(10);
    let mut signature_buffer = [0u8; 64];

    // let p1 = ParamTmpRef::new_input(user_id.as_bytes());
    let p0 = ParamTmpRef::new_output(&mut publickey_x);
    let p1 = ParamTmpRef::new_output(&mut publickey_y);
    let p2 = ParamTmpRef::new_input(&mut user_pub);
    let p3 = ParamTmpRef::new_output(&mut signature_buffer);
//     call operation from TEE

    println!("invoking operation");
    let mut operation = Operation::new(0, p0, p1, p2, p3);
    session.invoke_command(Command::GenKey as u32, &mut operation)?;

    // let publicx_size = operation.parameters().0.a() as usize;
    // let publicy_size = operation.parameters().0.b() as usize;
    //
    // publickey_x.clone_from_slice(&publickey[..32]);
    // publickey_y.clone_from_slice(&publickey[32..]);
    // let mut publicx_res = vec![0u8; publicx_size];
    // let mut publicy_res = vec![0u8; publicy_size];
    // publicx_res.copy_from_slice(&publickey_x[..publicx_size]);
    // publicy_res.copy_from_slice(&publickey_y[..publicy_size]);

    // returns vector of deruved secret
    Ok((publickey_x.to_vec(), publickey_y.to_vec(), signature_buffer.to_vec()))

//
}
/// Signature generation steps
/// 1) calculate message; h=hash(msg)
/// 2) generate random number k [random_key]
/// 3) calculate random point; R = k * G and take its x-cordinate: r=R.x
/// 4) calculate signature proof: s = k^-1 * (h + r * privkey)(mod n)
/// 5) Return signature r,s
/// @params:
/// msgdigest = derived_key
pub fn generate_sign(session: &mut Session, msgdigest: &[u8]) -> optee_teec::Result<[u8;64]> {
    let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut signature = [0u8; 64];

    let p1 = ParamTmpRef::new_output(&mut signature);
    let p2 = ParamTmpRef::new_input(&msgdigest);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);
    session.invoke_command(Command::Sign as u32, &mut operation)?;
    Ok(signature)
}



// digest functions
///Function verifying generated signature from [`generate_sign()`]
/// msgdigest = task public key
/// signature = generated signature
/// returns bool of verification
pub fn verify_sign(session: &mut Session, msgdigest: &[u8], signautre: [u8;64])
    -> optee_teec::Result<()> {
    let p0 = ParamTmpRef::new_input(&signautre);
    let p1 = ParamTmpRef::new_input(&msgdigest);
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(Command::Verify as u32, &mut operation);

    Ok(())
}
pub fn update(session: &mut Session, src: &[u8]) -> optee_teec::Result<()> {
    let p0 = ParamTmpRef::new_input(src);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::Update as u32, &mut operation)?;
    Ok(())
}

pub fn do_final(session: &mut Session, src: &[u8], res: &mut [u8]) -> optee_teec::Result<usize> {
    let p0 = ParamTmpRef::new_input(src);
    let p1 = ParamTmpRef::new_output(res);
    let p2 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

    session.invoke_command(Command::DoFinal as u32, &mut operation)?;

    Ok(operation.parameters().2.a() as usize)
}