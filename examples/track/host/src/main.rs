mod unix;
mod hotp;
mod key_gen;

use optee_teec::{
    Context,Session, Uuid,
};
use hotp::{get_hotp,register_shared_key};

use proto::{Command, UUID};


fn main() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    register_shared_key(&mut session)?;
    get_hotp(&mut session)?;

    println!("Success");
    Ok(())
}
