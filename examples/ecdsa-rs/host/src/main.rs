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
fn generate_sign(session: &mut Session, msgdigest: &[u8]) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut signature = [0u8; 64];

    let p1 = ParamTmpRef::new_output(&mut signature);
    let p2 = ParamTmpRef::new_input(&msgdigest);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);
    session.invoke_command(Command::Sign as u32, &mut operation)?;
    Ok(())
}
// fn verify(session: &mut Session, msgdigest: &[u8]) -> optee_teec::Result<()> {
//
// }


// digest functions
fn update(session: &mut Session, src: &[u8]) -> optee_teec::Result<()> {
    let p0 = ParamTmpRef::new_input(src);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::Update as u32, &mut operation)?;
    Ok(())
}

fn do_final(session: &mut Session, src: &[u8], res: &mut [u8]) -> optee_teec::Result<usize> {
    let p0 = ParamTmpRef::new_input(src);
    let p1 = ParamTmpRef::new_output(res);
    let p2 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

    session.invoke_command(Command::DoFinal as u32, &mut operation)?;

    Ok(operation.parameters().2.a() as usize)
}


fn main() -> optee_teec::Result<()> {

    let mut ctx = Context::new()?;

    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    generate_key(&mut session).unwrap();
    let mut hash: [u8; 32] = [0u8; 32];
    let input: Vec<String> = vec!["some".to_string(), "value".to_string()];
    for i in 0..input.len() {
        update(&mut session, input[i].as_bytes())?;
    }

    let hash_length = do_final(&mut session, input[input.len() -1].as_bytes(), &mut hash).unwrap();
    let mut res = hash.to_vec();
    res.truncate(hash_length as usize);

    println!("Get message hash as: {:?}.", res);
    // call generate_sign
    generate_sign(&mut session, &res[0..res.len()]);

    // generate_sign(&mut session);
    println!("Success");
    Ok(())
}

