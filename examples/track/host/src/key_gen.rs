use optee_teec::{Context, Operation, ParamType, Session, Uuid};
use optee_teec::{Error, ErrorKind, ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID};
use std::{env, str};
// key size of 20 bytes(20*8)
pub const key_size: u32 = 160;
// Generate key pair
fn gen_key(session: &mut Session, key_size: u32) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(key_size, 0, ParamType::ValueInput);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    // call session invoke to generate key
    session.invoke_command(Command::GenKey as u32, &mut operation)?;
    Ok(())
}


//
// fn main() -> optee_teec::Result<()> {
//     let args: Vec<String> = env::args().collect();
//     if args.len() != 3 {
//         println!(
//             "Receive {} arguments while 2 arguments are expected!",
//             args.len()
//         );
//         println!("Correct usage: passed 2 arguments as <key_size> and <string to encrypt>");
//         return Err(Error::new(ErrorKind::BadParameters));
//     }
//
//     let mut key_size = args[1].parse::<u32>().unwrap();
//     if key_size < 256 {
//         println!(
//             "Wrong key size {} is received. Use default minimal key size 256 instead.",
//             key_size
//         );
//         key_size = 256;
//     }
//
//     let mut ctx = Context::new()?;
//     let uuid = Uuid::parse_str(UUID).unwrap();
//     let mut session = ctx.open_session(uuid)?;
//
//     gen_key(&mut session, key_size)?;
//     enc_dec(&mut session, args[2].as_bytes())?;
//
//     Ok(())
// }
