
use optee_teec::{Context, Operation, ParamType, Session, Uuid, Result};
use optee_teec::{Error, ErrorKind, ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID, KEY_SIZE};
use std::{env, str};


/// function using ecc keypairs to derive ecdh shared key

pub fn derive_key(session: &mut Session, ecc_x: &Vec<u8>, ecc_y: &Vec<u8>) -> optee_teec::Result<(Vec<u8>)> {
   let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
   let mut derived_secret = [0u8;65];
   let p1 = ParamTmpRef::new_output(&mut derived_secret);
   let p2 = ParamTmpRef::new_input(ecc_x.as_slice());
   let p3 = ParamTmpRef::new_input(ecc_y.as_slice());
   let mut operation = Operation::new(0, p0, p1, p2, p3);

   session.invoke_command(Command::DeriveKey as u32, &mut operation)?;

   let key_size = operation.parameters().0.a() as usize;
   let mut derive_res = vec![0u8; key_size];
   derive_res.copy_from_slice(&derived_secret[..key_size]);
   println!("Derived shared secret {:?}", derive_res);
   Ok((derive_res))
}


