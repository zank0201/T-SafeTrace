#![feature(restricted_std)]
#![no_main]

mod dethmac;
use crate::dethmac::nistp256::Ecdsa;
pub use dethmac::*;

use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{AlgorithmId, Asymmetric,OperationMode, AttributeId, AttributeMemref, AttributeValue, Random, AE};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{TransientObject, TransientObjectType, ElementId};
use proto::{Command, Mode, BUFFER_SIZE, KEY_SIZE, TAG_LEN};


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
        Command::Sign => {
            return generate_sign(sess_ctx, _params);
        }
        Command::Update => {
            return update(sess_ctx, _params);
        }
        Command::DoFinal => {
            return do_final(sess_ctx, _params);
        }
        _ => {
            return Err(Error::new(ErrorKind::BadParameters));
        }
    }
}
pub fn update(digest: &mut Ecdsa, params: &mut Parameters) -> Result<()> {
    let mut p = unsafe { params.0.as_memref().unwrap() };
    let buffer = p.buffer();
    digest.digestop.update(buffer);
    Ok(())
}

pub fn do_final(digest: &mut Ecdsa, params: &mut Parameters) -> Result<()> {
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
