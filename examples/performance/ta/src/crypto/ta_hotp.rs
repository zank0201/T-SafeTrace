// mod self;
#![allow(unused)]
use optee_utee::Time;
use optee_utee::{AlgorithmId, Mac, Digest, Asymmetric, OperationMode};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::Command;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};


use std::convert::TryInto;
use std::iter::FromIterator;
use std::mem::replace;

pub use crate::crypto::{context::*};
pub use crate::storage::data::*;
use std::str;
//TODO get otp to sync with user's time
pub fn get_time() -> [u8; 8] {
    let start_time:u64 = 0;
    let time_step: u64 = 30;

    let mut time = Time::new();
    time.ree_time();
    let now_secs = time.seconds;
    let now_secs = now_secs as u64;

    let mut t= ((now_secs - start_time)/time_step).to_be_bytes();


    t

}


pub fn register_shared_key(hotp: &mut NewOperations, key_buffer: &mut [u8]) -> Result<()> {
    // let mut p = unsafe { params.0.as_memref().unwrap() };
    // let buffer = p.buffer();
    //


    hotp.key_len = key_buffer.len();
    // update counter value
    hotp.key[..hotp.key_len].clone_from_slice(&key_buffer);
    // let key_size = unsafe { params.0.as_value().unwrap().a() };
    // hotp.rsa_key =
    //     TransientObject::allocate(TransientObjectType::RsaKeypair, key_size as usize).unwrap();
    // hotp.key = hotp.rsa_key.generate_key(key_size as usize, &[])?;
    Ok(())

}

pub fn get_hotp(params: &mut Parameters) -> Result<()> {
    let mut hotp = NewOperations::default();
    let mut p0 = unsafe { params.0.as_value().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let user_pub = p1.buffer();
    // register_shared_key(&mut hotp)
    let mut io_key;
    match get_io_key(user_pub) {
        Ok(v) => io_key = v,
        Err(e) => return Err(e),
    };
    register_shared_key(&mut hotp, &mut io_key);
    let mut mac: [u8; SHA1_HASH_SIZE] = [0x0; SHA1_HASH_SIZE];


    hotp.counter = get_time();
    hmac_sha1(&mut hotp, &mut mac)?;

    let hotp_val = truncate(&mut mac);

    p0.set_a(hotp_val);

    Ok(())
}

pub fn hmac_sha1(hotp: &mut NewOperations, out: &mut [u8]) -> Result<usize> {
    if hotp.key_len < MIN_KEY_SIZE || hotp.key_len > MAX_KEY_SIZE {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    match Mac::allocate(AlgorithmId::HmacSha1, hotp.key_len * 8) {
        Err(e) => return Err(e),
        Ok(mac) => {
            match TransientObject::allocate(TransientObjectType::HmacSha1, hotp.key_len * 8) {
                Err(e) => return Err(e),
                Ok(mut key_object) => {
                    //KEY size can be larger than hotp.key_len
                    let mut tmp_key = hotp.key.to_vec();

                    tmp_key.truncate(hotp.key_len);

                    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &tmp_key);
                    key_object.populate(&[attr.into()])?;
                    mac.set_key(&key_object)?;
                }
            }
            mac.init(&[0u8; 0]);
            mac.update(&hotp.counter);
            let out_len = mac.compute_final(&[0u8; 0], out).unwrap();
            Ok(out_len)
        }
    }
}

pub fn truncate(hmac_result: &mut [u8]) -> u32 {
    let mut bin_code: u32;
    let offset: usize = (hmac_result[19] & 0xf) as usize;

    bin_code = ((hmac_result[offset] & 0x7f) as u32) << 24
        | ((hmac_result[offset + 1] & 0xff) as u32) << 16
        | ((hmac_result[offset + 2] & 0xff) as u32) << 8
        | ((hmac_result[offset + 3] & 0xff) as u32);

    bin_code %= DBC2_MODULO;
    return bin_code;
}
