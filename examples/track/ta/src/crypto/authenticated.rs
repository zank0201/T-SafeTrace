use optee_utee::{
    trace_println,
};
use optee_utee::{AlgorithmId, OperationMode, AE};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, Mode, BUFFER_SIZE, K_LEN, TAG_LEN};
pub use crate::crypto::context::{Operations};

pub fn prepare(ae: &mut Operations, params: &mut Parameters) -> Result<()> {
    trace_println!("is it me, am I the drama");
    let p0 = unsafe { params.0.as_value().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
trace_println!("I'm definitely the drama");
    let mode = match Mode::from(p0.a()) {
        Mode::Encrypt => OperationMode::Encrypt,
        Mode::Decrypt => OperationMode::Decrypt,
        _ => OperationMode::IllegalValue,
    };
    let nonce = p1.buffer();
    let key = p2.buffer();

    trace_println!("we are allocating object");

    ae.AeOp = AE::allocate(AlgorithmId::AesGcm, mode, K_LEN * 8).unwrap();
    trace_println!("we are allocating our key object");
    let mut key_object = TransientObject::allocate(TransientObjectType::Aes, K_LEN * 8).unwrap();
    trace_println!("we are attributing");
    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, key);
    key_object.populate(&[attr.into()])?;
    ae.AeOp.set_key(&key_object)?;
    ae.AeOp
        .init(&nonce, TAG_LEN * 8, 0, 0)?;
    Ok(())
}

pub fn auth_update(digest: &mut Operations, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let src = p0.buffer();
    let res = p1.buffer();
    digest.AeOp.update(src, res)?;
    trace_println!("Update digest");
    Ok(())
}

pub fn auth_encrypt(digest: &mut Operations, params: &mut Parameters) -> Result<()> {

    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };

    let mut clear = vec![0; p0.buffer().len() as usize];
    clear.copy_from_slice(p0.buffer());
    let mut ciph = vec![0; p1.buffer().len() as usize];
    ciph.copy_from_slice(p1.buffer());
    let mut tag = vec![0; p2.buffer().len() as usize];
    tag.copy_from_slice(p2.buffer());

    match digest.AeOp.encrypt_final(&clear, &mut ciph, &mut tag) {

        Err(e) => Err(e),
        Ok((_ciph_len, _tag_len)) => {
            p0.buffer().copy_from_slice(&clear);
            p1.buffer().copy_from_slice(&ciph);
            p2.buffer().copy_from_slice(&tag);


            Ok(())
        },

    }



}

pub fn auth_decrypt(digest: &mut Operations, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };

    let mut clear = vec![0; p0.buffer().len() as usize];
    clear.copy_from_slice(p0.buffer());
    let mut ciph = vec![0; p1.buffer().len() as usize];
    ciph.copy_from_slice(p1.buffer());
    let mut tag = vec![0; p2.buffer().len() as usize];
    tag.copy_from_slice(p2.buffer());

    trace_println!("tag = {:?} ", &tag);
    match digest.AeOp.decrypt_final(&clear, &mut ciph, &tag) {
        Err(e) => Err(e),
        Ok(_clear_len) => {
            p0.buffer().copy_from_slice(&clear);
            p1.buffer().copy_from_slice(&ciph);
            p2.buffer().copy_from_slice(&tag);

            Ok(())
        },
    }
}