#![allow(unused)]
use optee_teec::{
    Context, Error, ErrorKind, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session,
    Uuid,
};
use proto::{Command, UUID};
// size of test objects
const TEST_SIZE: usize = 10;
const SIZE_K: usize = 20;
// const RFC4226_TEST_VALUES: [u32; TEST_SIZE] = [
//     94287082, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
// ];

pub fn register_shared_key(session: &mut Session, k: &mut Vec<u8>) -> optee_teec::Result<()> {


    // // let k: [u8; SIZE_K] = [50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 0];
    //
    let p0 = ParamTmpRef::new_input(&k.as_slice());
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::RegisterSharedKey as u32, &mut operation)?;
    // let key_size :u32 = 160;
    // let p0 = ParamValue::new(key_size, 0, ParamType::ValueInput);
    // let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
    //
    // session.invoke_command(Command::RegisterSharedKey as u32, &mut operation)?;
    Ok(())
}

pub fn get_hotp(session: &mut Session) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
    // for i in 0..TEST_SIZE {
        session.invoke_command(Command::GetHOTP as u32, &mut operation)?;
        let (p0, _, _, _) = operation.parameters();
        let hotp_value = p0.a();

        println!("Get HOTP: {}", hotp_value);

        // if hotp_value != RFC4226_TEST_VALUES[i] {
        //     println!(
        //         "Wrong value get! Expected value: {}",
        //         RFC4226_TEST_VALUES[i]
        //     );
        //     return Err(Error::new(ErrorKind::Generic));
        // }
    // }
    Ok(())
}