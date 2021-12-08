use optee_teec::{
    Context,Session, Uuid,
};
use proto::{Command, Mode, AAD_LEN, BUFFER_SIZE, K_LEN, TAG_LEN, UUID};
// module to add new user
// ask user to create identity
pub fn add_user() -> optee_teec::Result<()>{

    // call new session and context
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    
    Ok(())
}