mod unix;
mod hotp;
mod key_gen;

use optee_teec::{
    Context,Session, Uuid,
};
use hotp::{get_hotp,register_shared_key};

use proto::{Command, UUID};


fn main() -> optee_teec::Result<()> {
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

    // TOTP main arguments
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    register_shared_key(&mut session)?;
    get_hotp(&mut session)?;

    println!("Success");
    Ok(())
}
