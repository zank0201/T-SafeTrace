#![allow(unused)]
use optee_teec::{
    Context, Error, ErrorKind, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session,
    Uuid,
};
use proto::{Command, UUID};
use rustc_hex::{FromHex, ToHex};
// size of test objects
const TEST_SIZE: usize = 10;
const SIZE_K: usize = 20;
// const RFC4226_TEST_VALUES: [u32; TEST_SIZE] = [
//     94287082, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
// ];


pub fn get_hotp(session: &mut Session, key: &str) -> optee_teec::Result<String> {
    let mut user_pub = &key[2..].from_hex().unwrap();
    let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let p1 = ParamTmpRef::new_input(&user_pub);
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    // for i in 0..TEST_SIZE {
        session.invoke_command(Command::GetHOTP as u32, &mut operation)?;
        let (p0, _, _, _) = operation.parameters();
        let hotp_value = p0.a();

        // println!("Get HOTP: {}", hotp_value);

        // if hotp_value != RFC4226_TEST_VALUES[i] {
        //     println!(
        //         "Wrong value get! Expected value: {}",
        //         RFC4226_TEST_VALUES[i]
        //     );
        //     return Err(Error::new(ErrorKind::Generic));
        // }
    // }
    Ok(hotp_value.to_string())
}