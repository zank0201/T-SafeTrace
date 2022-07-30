#![feature(restricted_std)]
#![no_main]
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, TransientObject, ta_open_session, trace_println,
};
#[macro_use]
extern crate lazy_static;


use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::Command;

pub mod crypto;

pub mod storage;

pub use crypto::*;
use crate::ta_hotp::*;
use crate::nistp256::*;
use crate::ta_keygen::*;
use crate::randomGen::*;
use crate::authenticated::*;
use crate::storage::*;
use ta_hotp::{register_shared_key, get_hotp, hmac_sha1, truncate};
use ta_keygen::generate_key;
use storage::{data::*, trusted_keys::KeyStorage};



pub const SHA1_HASH_SIZE: usize = 20;
pub const MAX_KEY_SIZE: usize = 64;
pub const MIN_KEY_SIZE: usize = 10;
pub const DBC2_MODULO: u32 = 100000000;

#[ta_create]
fn create() -> Result<()> {
    // trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut KeyStorage) -> Result<()> {
    // trace_println!("[+] TA open session");

    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut KeyStorage) {

    // trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    // trace_println!("[+] TA destroy");
}

#[ta_invoke_command]
fn invoke_command(_sess_ctx: &mut KeyStorage, cmd_id: u32, _params: &mut Parameters) -> Result<()> {
    // trace_println!("[+] TA invoke command");
        match Command::from(cmd_id) {

        Command::GetHOTP => {
            return get_hotp(_params);
        }

        Command::GenKey => {
            // trace_println!("Ecdsa keypair generate");
            return ecdsa_keypair(_params);
        }


        Command::Prepare => {

            return add_data_object(_sess_ctx, _params);
        }
        Command::Report => {
            return create_raw_object(_sess_ctx, _params);
        }

        Command::FindMatch => {
            return find_match_optee(_sess_ctx, _params);
        }

        _ => {
            return Err(Error::new(ErrorKind::BadParameters));
        }

    }

}


// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 = 2*32*32*1024;
const TA_STACK_SIZE: u32 = 10*4* 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"Track and trace.\0";
const EXT_PROP_VALUE_1: &[u8] = b"Thesis TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
