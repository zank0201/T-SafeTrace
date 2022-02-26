#![allow(unused_imports)]
#![allow(unused)]
use optee_teec::{Operation, ParamType, Session};
use optee_teec::{Error, ErrorKind, ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID, KEY_SIZE};
use std::{env, str};
use rustc_hex::{FromHex, ToHex};
use hex::encode;

/// function using ecc keypairs to derive ecdh shared key

pub fn derive_key(session: &mut Session, user_pubkey: &str) -> optee_teec::Result<Vec<u8>> {
   let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
   let mut derived_secret = [0u8;65];
   let new_array = &user_pubkey[2..].from_hex().unwrap();

   // let mut ecc_x = [0u8;64];
   // let mut ecc_y = [0u8;64];
   // ecc_x.clone_from_slice(&new_array.from_hex().unwrap()[..64]);
   // println!("length of user_pubkey{:?}", user_pubkey.as_bytes().len());
   //
   // ecc_y.clone_from_slice(&new_array.from_hex().unwrap()[..]);
   let p1 = ParamTmpRef::new_output(&mut derived_secret);
   let p2 = ParamTmpRef::new_input(&new_array);
   // let p3 = ParamTmpRef::new_input(&ecc_y);
   let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

   session.invoke_command(Command::DeriveKey as u32, &mut operation)?;

   let key_size = operation.parameters().0.a() as usize;

   let mut derive_res = vec![0u8; key_size];
   derive_res.copy_from_slice(&derived_secret[..key_size]);

   Ok(derive_res)
}


