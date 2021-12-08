// use optee_teec::ParamNone;
// use optee_teec::{Context, Operation, Session, Uuid};
// use proto::{Command, UUID};
//
// pub fn time(session: &mut Session) -> optee_teec::Result<()> {
//     let mut operation = Operation::new(0, ParamNone, ParamNone, ParamNone);
//     session.invoke_command(Command::Test as u32, &mut operation)?;
//
//     Ok(())
// }
