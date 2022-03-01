use optee_teec::{Context, ErrorKind, Operation, ParamNone, ParamTmpRef, Session,ParamValue, ParamType, Uuid};
use proto::{Command, UUID, StorageMode};
use std::ffi::CString;




/// function which will read data within secure storage
/// this will read data to find match in data
/// parameters:
/// obj_id: shared secret of user
/// enc_data: output buffer encrypted data of user(Location data)

pub fn read_object(session: &mut Session,
                   obj_id: &[u8],
                   enc_data: &mut [u8]) -> optee_teec::Result<()> {
    let p0 = ParamTmpRef::new_input(obj_id);
    let p1 = ParamTmpRef::new_output(enc_data);
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    session.invoke_command(Command::Read as u32, &mut operation)?;

    Ok(())
}

///adds new data to secure storage
/// @param:
/// obj_id: shared secret
/// enc_data: encrypted data of user(Location data)
/// we can overwrite data using the correct flag
/// this function is [`add_user_data`]
pub fn add_data(
    session: &mut Session,
    obj_id: &[u8],
    obj_data: &[u8],
    mode: StorageMode,
) -> optee_teec::Result<()> {
    let p0 = ParamTmpRef::new_input(obj_id);
    let p1 = ParamTmpRef::new_input(obj_data);
    let p2 = ParamValue::new(mode as u32, 0, ParamType::ValueInput);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

    session.invoke_command(Command::Write as u32, &mut operation)?;

    Ok(())
}
pub fn delete_obj(
    session: &mut Session,
    obj_id: &[u8])
    -> optee_teec::Result<()> {

    let p0 = ParamTmpRef::new_input(obj_id);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::Delete as u32, &mut operation)?;
    Ok(())
}