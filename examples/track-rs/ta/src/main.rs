#![feature(restricted_std)]
#![no_main]
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
#[macro_use]
extern crate lazy_static;
use optee_utee::{AlgorithmId, Mac};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::Command;
use optee_utee::{Asymmetric,};

pub mod crypto;

pub mod storage;

pub use crypto::*;
use crate::ta_hotp::*;
use crate::nistp256::*;
use crate::ta_keygen::*;
use crate::randomGen::*;
use crate::authenticated::*;
use ta_hotp::{register_shared_key, get_hotp, hmac_sha1, truncate};
use ta_keygen::generate_key;
use storage::data::*;


pub const SHA1_HASH_SIZE: usize = 20;
pub const MAX_KEY_SIZE: usize = 64;
pub const MIN_KEY_SIZE: usize = 10;
pub const DBC2_MODULO: u32 = 100000000;
// struct containing public key and secret key


#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut Operations) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut Operations) {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}

#[ta_invoke_command]
fn invoke_command(sess_ctx: &mut Operations, cmd_id: u32, _params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::RegisterSharedKey => {
            return register_shared_key(sess_ctx, _params);
        }
        Command::GetHOTP => {
            return get_hotp(sess_ctx, _params);
        }
        Command::DeriveKey => {
            return generate_key(sess_ctx, _params);
        }
        // call prepare function using input data from host
        Command::GenKey => {
            return ecdsa_keypair(sess_ctx, _params);
        }

        Command::Sign => {
            return generate_sign(sess_ctx, _params);
        }
        Command::Update => {
            return update(sess_ctx, _params);
        }
        Command::Prepare => {
            return prepare(sess_ctx, _params);
        }
        Command::AuthUpdate => {
            trace_println!("invoke update");
            return auth_update(sess_ctx, _params);
        }
        Command::EncFinal => {
            trace_println!("invoke encrypt");
            return auth_encrypt(sess_ctx, _params);
        }
        Command::DecFinal => {
            trace_println!("invoke decrypt");
            return auth_decrypt(sess_ctx, _params);
        }
        Command::DoFinal => {
            return do_final(sess_ctx, _params);
        }
        // Command::Start => {
        //     trace_println!("invoke start");
        //     return tcp_client();
        // }

        Command::RandomGenerator => {
            return random_number_generate(_params);
        }
// storage functions
//         Command::Write => {
//             return create_raw_object(sess_ctx,_params);
//         }
        Command::Read => {
            return read_raw_object(_params);
        }
        Command::Delete => {
            return delete_object(_params);
        }

        _ => {
            return Err(Error::new(ErrorKind::BadParameters));
        }
    }
}


// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 =96 * 1024;
const TA_STACK_SIZE: u32 = 6 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"This is an HOTP example.\0";
const EXT_PROP_VALUE_1: &[u8] = b"Thesis TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2*2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
