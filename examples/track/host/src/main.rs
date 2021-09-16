mod unix;
mod hotp;
mod host_keygen;

use optee_teec::{
    Context,Session, Uuid,
};
use hotp::{get_hotp,register_shared_key};
use host_keygen::{generate_key};

use proto::{Command, UUID};


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

    println!("Success");
    Ok(())
}
