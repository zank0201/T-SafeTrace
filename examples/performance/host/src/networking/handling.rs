use crate::networking::messages::*;
use crate::networking::Ipc_Listener::EnclaveClient;
use crate::data::*;
use std::str;
use rmp_serde::Deserializer;
use serde::Deserialize;
use serde_json::Value;
use crate::crypt::*;
use rustc_hex::{FromHex, ToHex};
use proto::{Command, Mode,AAD_LEN, BUFFER_SIZE, K_LEN, TAG_LEN, UUID};
// create function to  call public key from TA(encryption key)
// use to clean up code from main file
type ResponseResult = Result<IpcResponse, Error>;
use failure::Error;
use optee_teec::{
     Session, Uuid
};

pub fn get_ta_report(session: &mut Session) ->ResponseResult {

    let mut signing_key = report::ta_report(&mut *session).unwrap();
    let result = IpcResults::EnclaveReport { signing_key: signing_key.to_hex()};
    Ok(IpcResponse::GetEnclaveReport { result })

}
pub fn new_task_encryption_key(session: &mut Session, user_pubkey: &str) -> ResponseResult {

    let (mut ecc_x, mut ecc_y, mut sign) = host_ecdsa::ecdsa_keypair(&mut *session, user_pubkey).unwrap();
    let enclave_result = Keypair {
        pubkeyX: ecc_x.clone().to_hex(),
        pubkeyY: ecc_y.clone().to_hex()
    };



    let result = IpcResults::DHKey {taskPubKey: enclave_result.hex_keypair(), sig: sign.to_hex()};
    Ok(IpcResponse::NewTaskEncryptionKey { result })
}

pub fn add_personal_data(input: IpcInputData, session: &mut Session) -> ResponseResult {
    // this needs to be decrypted

    let encrypted_userid = input.encrypted_userid.from_hex()?;
    let encrypted_data = input.encrypted_data.from_hex()?;
    let key = input.user_pub_key;
    let sig = input.user_sig.from_hex()?;


    let mut useridlen = &encrypted_userid[..encrypted_userid.len()-28];
    let mut data_len = &encrypted_data[..encrypted_data.len()-28];

    let mut id_ciph = vec![0x00u8; useridlen.len()];
    let mut data_ciph = vec![0x00u8; data_len.len()];

    let user_stat = authenticated::add_data(&mut *session,&encrypted_userid, &key, &encrypted_data, &sig).unwrap();
    // let data_stat = authenticated::decrypt(&mut *session, 1, &encrypted_data, &key, &mut data_ciph).unwrap();
    let result;
    if (user_stat)==0 {
        result = IpcResults::AddPersonalData { status: Status::Passed };
    } else {
            result =IpcResults::AddPersonalData { status: Status::Failed };
        }



    // let result = IpcResults::AddPersonalData { status: Status::Passed };
    Ok(IpcResponse::AddPersonalData { result })

}
// returns encrypted geolocation data
pub fn find_match(session: &mut Session, input: IpcInputMatch) -> ResponseResult  {


    let key = input.user_pub_key;
    let encrypted_userid = input.encrypted_userid.from_hex()?;

    let authenticated_output = authenticated::find_match_optee(&mut *session, &encrypted_userid, &key).unwrap();



    let result = IpcResults::FindMatch { status: Status::Passed, encryptedOutput: authenticated_output};
    Ok(IpcResponse::FindMatch { result })
}

pub fn generateTotp(session: &mut Session, user_pubkey: &str) -> ResponseResult {

    let token = hotp::get_hotp(&mut *session, user_pubkey)?;
    let result = IpcResults::Totp {token: token};
    Ok(IpcResponse::getTotpKey { result })


}
//TODO add test fn