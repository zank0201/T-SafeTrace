use optee_teec::{Context, Operation, ParamType, Session, Uuid, Result};
use optee_teec::{Error, ErrorKind, ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID, KEY_SIZE};
use std::{env, str};


/// function using ecc keypairs to derive ecdh shared key

pub fn generate_key(session: &mut Session) -> Result<(Vec<u8>, Vec<u8>)> {
    // prime base vector
    // vector needs to change to 20 byte vector
    let prime_base = [0xB6, 0x73, 0x91, 0xB5, 0xD6, 0xBC, 0x95, 0x73,
        0x0D, 0x53, 0x64, 0x13, 0xB0, 0x51, 0xC6, 0xB4,
        0xEB, 0x9D, 0x74, 0x57, 0x8D, 0x65, 0x3A, 0x4B,
        0x7A, 0xB2, 0x93, 0x27, 0xA6, 0xC1, 0xBC, 0xAB,
        5];
    // input vector to ta
    let p0 = ParamTmpRef::new_input(&prime_base);
    // new paramater of type output
    let p1 = ParamValue::new(0, 0, ParamType::ValueOutput);
//     initialise public and public key vectors
    let mut public_key = [0u8; KEY_SIZE];
    let mut private_key = [0u8; KEY_SIZE];
//     push vectors to ta as output
    let p2 = ParamTmpRef::new_output(&mut public_key);
    let p3 = ParamTmpRef::new_output(&mut private_key);

    let mut operation = Operation::new(0, p0, p1, p2, p3);
    session.invoke_command(Command::GenerateKey as u32, &mut operation)?;

//     Take output from Ta, size of array and actual vector values
    let public_size = operation.parameters().1.a() as usize;
    let private_size = operation.parameters().1.b() as usize;

    let mut public_res = vec![0u8; public_size];
    let mut private_res = vec![0u8; private_size];
    public_res.copy_from_slice(&public_key[..public_size]);
    private_res.copy_from_slice(&private_key[..private_size]);

//     return tuple of public and private keys
    Ok((public_res, private_res))
}


