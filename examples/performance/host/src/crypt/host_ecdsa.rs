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

    // println!("invoking operation");
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
