#![allow(unused_imports)]
#![allow(unused)]
use optee_teec::{
    Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid,
};
// const PREFIX: &'static [u8; 19] = b"Enigma User Message";
// use hex::{FromHex, ToHex};

use std::str;
use rmp_serde::Deserializer;
use serde::Deserialize;
use serde_json::Value;
use proto::{Command,  AAD_LEN, BUFFER_SIZE, KEY_SIZE, UUID};

pub fn ta_report(session: &mut Session) -> optee_teec::Result<Vec<u8>> {
    let mut signing_key = [0u8; 32];

    let p0 = ParamTmpRef::new_output(&mut signing_key);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
    session.invoke_command(Command::Report as u32, &mut operation)?;
    Ok(signing_key.to_vec())
}