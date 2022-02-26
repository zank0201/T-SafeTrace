#![allow(unused_imports)]
use optee_teec::{Context, Operation, ParamNone, ParamTmpRef, Session, Uuid};
use proto::{Command, UUID};

pub fn random(session: &mut Session) -> optee_teec::Result<([u8;12])> {
    let mut tmp_iv = [0u8; 12];

    let p0 = ParamTmpRef::new_output(&mut tmp_iv);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::RandomGenerator as u32, &mut operation)?;

    Ok(tmp_iv)
}
// pub fn random_uuid(session: &mut Session) -> optee_teec::Result<()> {
//     // call random function and use to generate random uuid
//     let mut random_uuid = random(session).unwrap();
//     let generate_uuid = Uuid::from_slice(&random_uuid).unwrap();
//     println!("Generated uuid {}", &generate_uuid);
//     Ok(())
// }