use optee_teec::{
    Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid,
};
use proto::{Command, Mode, AAD_LEN, BUFFER_SIZE, K_LEN, TAG_LEN, UUID};


pub fn prepare(
    session: &mut Session,
    mode: Mode,
    nonce: &[u8],
    key: &[u8],
) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(mode as u32, 0, ParamType::ValueInput);
    let p1 = ParamTmpRef::new_input(nonce);
    let p2 = ParamTmpRef::new_input(key);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

    session.invoke_command(Command::Prepare as u32, &mut operation)?;
    Ok(())
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