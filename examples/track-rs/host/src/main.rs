#![allow(unused_imports)]
#![allow(unused)]
mod unix;
mod hotp;
mod host_keygen;
mod host_ecdsa;
mod data;
pub mod networking;
// mod UserInterface;


use optee_teec::{
    Context,Session, Uuid,
};

use futures::Future;
use networking::{Ipc_Listener, IpcListener};
use crate::data::randomGen::*;
use crate::data::authenticated::*;
use hotp::{get_hotp,register_shared_key};
use host_keygen::{derive_key};
use host_ecdsa::{ecdsa_keypair, generate_sign, update, do_final};

use proto::{Command, Mode, AAD_LEN, BUFFER_SIZE, K_LEN, TAG_LEN, UUID};



fn main() -> optee_teec::Result<()> {

    let server = IpcListener::new(&format!("tcp://*:5552"));

    // TOTP main arguments
    let mut ctx = Context::new()?;

    let uuid = Uuid::parse_str(UUID).unwrap();

    let mut session = ctx.open_session(uuid)?;
    // DH key generation

    server
        .run(move |multi| Ipc_Listener::handle_message(multi,1, &mut session))
        .wait()
        .unwrap();


    // let(mut ecc_x, mut ecc_y) =  ecdsa_keypair(&mut session).unwrap();

    let mut hash: [u8; 32] = [0u8; 32];

    // generate ecdh shared secret to use for encryption, decryption and others
//     let mut shared_secret = derive_key(&mut session, &mut ecc_x, &mut ecc_y).unwrap();
//     // call digest from ta
//     update(&mut session, &shared_secret);
//     let hash_length = do_final(&mut session, &shared_secret, &mut hash).unwrap();
//     let mut res = hash.to_vec();
//     res.truncate(hash_length as usize);
//
//     println!("Get message hash as: {:?}.", res);
//     // call generate_sign
//
//     generate_sign(&mut session, &res[0..res.len()]);
//
//     register_shared_key(&mut session, &mut shared_secret)?;
//     get_hotp(&mut session)?;
//
//     // call authenticated encryption functions
//     let key = shared_secret.as_slice();
//     let nonce = random(&mut session).unwrap();
//     let clear = b"I am a string that we will use".to_vec();
//     let clear2 = clear.clone();
//     let mut ciph1 = [0x00u8; BUFFER_SIZE];
//     let mut ciph2 = [0x00u8;BUFFER_SIZE];
//
//     let mut tmp1 = [0x00u8; BUFFER_SIZE];
//     let mut tmp2 = [0x00u8; BUFFER_SIZE];
//     let mut tag = [0x00u8; TAG_LEN];
// // call authenticated encryption prepare function
//     prepare(&mut session, Mode::Encrypt, &nonce, &key)?;
//     // call update function
//     aes_update(&mut session, &clear, &mut ciph1)?;
//     // call encrypt function
//     aes_encrypt(&mut session, &clear2, &mut ciph2, &mut tag)?;
//     // call decryption functions
//     println!("tag from host {:?}", &tag);
//     println!("ciph1 from host {:?}", &ciph1);
//     println!("ciph2 from host {:?}", &ciph2);
//     prepare(&mut session, Mode::Decrypt, &nonce, &key);
//     aes_update(&mut session, &ciph1, &mut tmp1)?;
//     aes_decrypt(&mut session, &ciph2, &mut tmp2, &tag)?;
//
//     // checking if text and decode text match
//     let mut clear_total = clear.to_vec();
//     clear_total.extend_from_slice(&clear2);
//     let mut tmp_total = tmp1.to_vec();
//     tmp_total.extend_from_slice(&tmp2);
//     if clear_total
//         .iter()
//         .zip(tmp_total.iter())
//         .all(|(a, b)| a == b)
//     {
//         println!("Clear text and decoded text match");
//         println!("clear text {:?}",&clear_total);
//         println!("decoded text {:?}", &tmp_total);
//     } else {
//         println!("Clear text and decoded text differ => ERROR");
//     }
//     // random_uuid(&mut session);
//     // tcp_client();
//
//     println!("testing bind");

    println!("Success");
    Ok(())
}
