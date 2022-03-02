#![allow(unused_imports)]
#![allow(unused)]


mod data;
pub mod networking;
// mod UserInterface;
pub mod crypt;

use optee_teec::{
    Context,Session, Uuid,
};

use futures::Future;
use networking::{Ipc_Listener, IpcListener};
// use crate::data::randomGen::*;
// use crate::data::authenticated::*;
// // use hotp::{get_hotp,register_shared_key};
// use host_keygen::{derive_key};
// use host_ecdsa::{ecdsa_keypair, generate_sign, update, do_final};
//
use proto::{Command, Mode, AAD_LEN, BUFFER_SIZE, K_LEN, TAG_LEN, UUID};
//

fn main() -> optee_teec::Result<()> {


    let mut ctx = Context::new()?;

    let uuid = Uuid::parse_str(UUID).unwrap();

    let mut session = ctx.open_session(uuid).unwrap();
    // TOTP main arguments



    // DH key generation
    let server = IpcListener::new(&format!("tcp://*:5552"));
    server
        .run(move |multi|
            Ipc_Listener::handle_message(multi,1, &mut session))
        .wait()
        .unwrap();


    println!("Success");
    Ok(())
}
