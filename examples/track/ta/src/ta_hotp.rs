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
use num_bigint::{BigInt, ToBigInt, Sign};

use std::str;
pub const SHA1_HASH_SIZE: usize = 20;
pub const MAX_KEY_SIZE: usize = 64;
pub const MIN_KEY_SIZE: usize = 10;
pub const DBC2_MODULO: u32 = 100000000;

// Add transient object

pub struct HmacOtp {
    pub counter: [u8; 8],
    pub key: [u8; MAX_KEY_SIZE],
    pub dh_key: TransientObject,
    pub key_len: usize,
}

impl Default for HmacOtp {
    fn default() -> Self {
        Self {
            counter: [0u8; 8],
            key: [0u8; MAX_KEY_SIZE],
            dh_key: TransientObject::null_object(),
            key_len: 0,
        }
    }
}


pub fn get_time(hotp: &mut HmacOtp) -> [u8; 8] {
    let start_time:u64 = 0;
    let time_step: u64 = 30;

    let mut time = Time::new();
    time.ree_time();
    let now_secs = time.seconds;
    let now_secs = now_secs as u64;

    let mut t= ((now_secs - start_time)/time_step).to_be_bytes();


    trace_println!("{:?}", t);
    t

}
// converts hex string to Byte
// pub fn hexStrtoBytes(string_hex: String) -> String {
//     let hash = string_hex.as_bytes();
//     return hash.to_hex();
// }


pub fn register_shared_key(hotp: &mut HmacOtp,params: &mut Parameters) -> Result<()> {
    let mut p = unsafe { params.0.as_memref().unwrap() };
    let buffer = p.buffer();


    trace_println!("[+] buffer = {:?}",&buffer);
    hotp.key_len = buffer.len();
    // update counter value
    hotp.key[..hotp.key_len].clone_from_slice(buffer);
    // let key_size = unsafe { params.0.as_value().unwrap().a() };
    // hotp.rsa_key =
    //     TransientObject::allocate(TransientObjectType::RsaKeypair, key_size as usize).unwrap();
    // hotp.key = hotp.rsa_key.generate_key(key_size as usize, &[])?;
    Ok(())

}

pub fn get_hotp(hotp: &mut HmacOtp, params: &mut Parameters) -> Result<()> {
    let mut mac: [u8; SHA1_HASH_SIZE] = [0x0; SHA1_HASH_SIZE];

    hotp.counter = get_time(hotp);
    hmac_sha1(hotp, &mut mac)?;
    trace_println!("[+] Hmac value = {:?}",&mac);

    let hotp_val = truncate(&mut mac);
    let mut p = unsafe { params.0.as_value().unwrap() };
    p.set_a(hotp_val);
    Ok(())
}

pub fn hmac_sha1(hotp: &mut HmacOtp, out: &mut [u8]) -> Result<usize> {
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
    trace_println!("bin_code{:?}", bin_code);
    bin_code %= DBC2_MODULO;
    return bin_code;
}
