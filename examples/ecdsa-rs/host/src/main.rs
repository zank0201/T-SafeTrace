mod octal;
use octal::{decode_hex, encode_hex};
use optee_teec::{
    Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid,
};

use proto::{Command, Mode, AAD_LEN, BUFFER_SIZE, KEY_SIZE, UUID};


/// Function taking in edcsa paramaters for P-256
/// parameters:
/// 1) session
/// returns private key generated from ta
fn generate_key(session: &mut Session) -> optee_teec::Result<()> {

    //TODO integrate edcsa from https://github.com/OP-TEE/optee_os/issues/1378

    // output arrays to get private and public values
    let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut private_key = [0u8; KEY_SIZE];
    let mut publickey_x = [0u8; KEY_SIZE];
    let mut publickey_y = [0u8; KEY_SIZE];

    let p0 = ParamTmpRef::new_output(&mut private_key);
    let p1 = ParamTmpRef::new_output(&mut publickey_x);
    let p2 = ParamTmpRef::new_output(&mut publickey_y);
//     call operation from TEE
    println!("invoking operation");
    let mut operation = Operation::new(0, p0, p1, p2,ParamNone);
    session.invoke_command(Command::GenKey as u32, &mut operation)?;

    // let publicx_size = operation.parameters().0.a() as usize;
    // let mut public_res = vec![0u8; publicx_size];
    // public_res.copy_from_slice(&publickey_x[..publicx_size]);
    // println!("print public key generated {:?}", &public_res);

    Ok(())

//
}
/// Signature generation steps
/// 1) calculate message; h=hash(msg)
/// 2) generate random number k [random_key]
/// 3) calculate random point; R = k * G and take its x-cordinate: r=R.x
/// 4) calculate signature proof: s = k^-1 * (h + r * privkey)(mod n)
/// 5) Return signature r,s
// fn generate_sign(session: &mut Session) -> optee_teec::Result<()> {
//     let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
//     let mut signature = [0u8; KEY_SIZE];
//
//     let p1 = ParamTmpRef::new_output(&mut &signature);
//     let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
//     session.invoke_command(Command::Sign as u32, &mut operation)?;
//     Ok(())
// }

//TODO create function to derive hmac drbg


fn main() -> optee_teec::Result<()> {

    let mut ctx = Context::new()?;

    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;
    // empty array for generated key
    // call funtion to generate random key
    // let key =  random_key(&mut session).unwrap();
    // let nonce = random_nonce(&mut session);
    // call prepare function to initiate signing
    generate_key(&mut session).unwrap();

    // generate_sign(&mut session);
    println!("Success");
    Ok(())
}

