#![allow(unused_imports)]
use optee_teec::{
    Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid,
};
use proto::{Command, Mode, AAD_LEN, BUFFER_SIZE, K_LEN, TAG_LEN, UUID};
use rustc_hex::{FromHex, ToHex};
//entry point for any encrypted data going to storage
// input used public key is used to find derived key
// derived key is used
use rmp_serde::Deserializer;
use serde::Deserialize;
use serde_json::{Value, json};
const TEST_OBJECT_SIZE: usize = 7000;
pub fn add_data(
    session: &mut Session,
    user_id: &[u8],
    key: &str,
    data: &[u8],
    sig: &[u8]
) -> optee_teec::Result<u32> {
    // let mut buffer = vec![0u8;data.len() as usize];
    let mut user_pub = &key[2..].from_hex().unwrap();
    let p0 = ParamTmpRef::new_input(&sig);
    let p1 = ParamTmpRef::new_input(user_id);

    let p2 = ParamTmpRef::new_input(&user_pub);
    let p3 = ParamTmpRef::new_input(data);
    let mut operation = Operation::new(0, p0, p1, p2, p3);

    session.invoke_command(Command::Prepare as u32, &mut operation)?;
    // let session_status = operation.parameters().0.a() as u32;
    //
    // let result;
    // if session_status == 0 {
    //     result = 0;
    // }else{
    //     result = 1;
    //     }

    Ok(0)
}

pub fn find_match_optee(session: &mut Session,
                        user_id: &[u8],
                        key: &str) -> optee_teec::Result<String> {

    // let mut data_buffer = vec![0u8; 10];
    //read buffer to put data through encryption for frontend
    // let mut encrypted_output = vec![0u8; encrypted_output.len()];
    let mut buffer = [0u8; 120];
    let mut user_pub = &key[2..].from_hex().unwrap();
    // let p0 = ParamTmpRef::new_input(&mut encrypted_output);
    let p0 = ParamTmpRef::new_input(user_id);
    let p1 = ParamTmpRef::new_input(&user_pub);
    let p2 = ParamTmpRef::new_output(&mut buffer);
    // let p3 = ParamTmpRef::new_output(&mut data_buffer);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

    session.invoke_command(Command::FindMatch as u32, &mut operation)?;
    //
    // println!("encrypted out {:?}", &encrypted_output.to_hex());
    Ok(buffer.to_hex())

}


pub fn aes_update(session: &mut Session, src: &[u8], res: &mut [u8]) -> optee_teec::Result<()> {
    let p0 = ParamTmpRef::new_input(src);
    let p1 = ParamTmpRef::new_output(res);
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    session.invoke_command(Command::AuthUpdate as u32, &mut operation)?;

    Ok(())
}

pub fn aes_encrypt(session: &mut Session, src: &[u8], res: &mut [u8], tag: &mut [u8],) -> optee_teec::Result<()> {
    let p0 = ParamTmpRef::new_input(src);
    let p1 = ParamTmpRef::new_output(res);
    let p2 = ParamTmpRef::new_output(tag);

    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

    session.invoke_command(Command::EncFinal as u32, &mut operation)?;

    Ok(())
}

pub fn aes_decrypt(session: &mut Session,
                   src: &[u8],
                   res: &mut [u8],
                   tag: &[u8],) -> optee_teec::Result<()> {


    let p0 = ParamTmpRef::new_input(src);
    let p1 = ParamTmpRef::new_output(res);
    let p2 = ParamTmpRef::new_input(tag);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);
    session.invoke_command(Command::DecFinal as u32, &mut operation)?;
    Ok(())
}