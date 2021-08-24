use optee_teec::{Context, Operation, ParamType, Session, Uuid};
use optee_teec::{Error, ErrorKind, ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID};
use std::{env, str};

fn gen_key(session: &mut Session, key_size: u32) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(key_size, 0, ParamType::ValueInput);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::GenKey as u32, &mut operation)?;

    Ok(())
}

fn enc_dec(session: &mut Session, plain_text: &[u8]) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::GetSize as u32, &mut operation)?;

    let mut cipher_text = vec![0u8; operation.parameters().0.a() as usize];
    let p0 = ParamTmpRef::new_input(plain_text);
    let p1 = ParamTmpRef::new_output(&mut cipher_text);
    let mut operation2 = Operation::new(0, p0, p1, ParamNone, ParamNone);

    session.invoke_command(Command::Encrypt as u32, &mut operation2)?;
    println!(
        "Success encrypt input text \"{}\" as {} bytes cipher text: {:?}",
        str::from_utf8(plain_text).unwrap(),
        cipher_text.len(),
        cipher_text
    );

    let p0 = ParamTmpRef::new_input(&cipher_text);
    let mut dec_res: Vec<u8> = vec![0u8; plain_text.len()];
    let p1 = ParamTmpRef::new_output(&mut dec_res);
    let mut operation2 = Operation::new(0, p0, p1, ParamNone, ParamNone);

    session.invoke_command(Command::Decrypt as u32, &mut operation2)?;
    println!(
        "Success decrypt the above ciphertext as {} bytes plain text: {}",
        dec_res.len(),
        str::from_utf8(&dec_res).unwrap()
    );
    Ok(())
}