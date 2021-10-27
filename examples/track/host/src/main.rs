mod unix;
mod hotp;
mod host_keygen;
mod host_ecdsa;

use optee_teec::{
    Context,Session, Uuid,
};
use hotp::{get_hotp,register_shared_key};
use host_keygen::{generate_key};
use host_ecdsa::{ecdsa_keypair, generate_sign, update, do_final};

use proto::{Command,AAD_LEN, BUFFER_SIZE, KEY_SIZE, UUID};


fn main() -> optee_teec::Result<()> {


    // TOTP main arguments
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;
    // DH key generation
    let (mut key0_public, key0_private) = generate_key(&mut session).unwrap();
    println!("get key 0 pair as public: {:?}, private: {:?}",
    key0_public, key0_private);
    // gen_key(&mut session, 256)?;
    println!("HOTP");
    register_shared_key(&mut session)?;
    get_hotp(&mut session)?;


    ecdsa_keypair(&mut session).unwrap();
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
    println!("Success");
    Ok(())
}
