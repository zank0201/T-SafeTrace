// Need to generate a random key
// that can be authenticated with the data we have
use optee_utee::trace_println;
use optee_utee::{AlgorithmId, Asymmetric, OperationMode};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{TransientObject, TransientObjectType};
use proto::Command;

pub struct RsaCipher {
    pub key: TransientObject,
}

impl Default for RsaCipher {
    fn default() -> Self {
        Self {
            key: TransientObject::null_object(),
        }
    }
}

pub fn gen_key(rsa: &mut RsaCipher, params: &mut Parameters) -> Result<()> {
    let key_size = unsafe { params.0.as_value().unwrap().a() };
    rsa.key =
        TransientObject::allocate(TransientObjectType::RsaKeypair, key_size as usize).unwrap();
    rsa.key.generate_key(key_size as usize, &[])?;

    Ok(())
}

// gets key size from generated key
pub fn get_size(rsa: &mut RsaCipher, params: &mut Parameters) -> Result<()> {
    let key_info = rsa.key.info().unwrap();
    unsafe {
        params
            .0
            .as_value()
            .unwrap()
            .set_a((key_info.object_size() / 8) as u32)
    };
    Ok(())
}

pub fn encrypt(rsa: &mut RsaCipher, params: &mut Parameters) -> Result<()> {
    let key_info = rsa.key.info().unwrap();
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let plain_text = p0.buffer();
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    match Asymmetric::allocate(
        AlgorithmId::RsaesPkcs1V15,
        OperationMode::Encrypt,
        key_info.object_size(),
    ) {
        Err(e) => Err(e),
        Ok(cipher) => {
            cipher.set_key(&rsa.key)?;
            match cipher.encrypt(&[], &plain_text) {
                Err(e) => Err(e),
                Ok(cipher_text) => Ok(p1.buffer().clone_from_slice(&cipher_text)),
            }
        }
    }
}

pub fn decrypt(rsa: &mut RsaCipher, params: &mut Parameters) -> Result<()> {
    let key_info = rsa.key.info().unwrap();
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut cipher_text = p0.buffer();
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    match Asymmetric::allocate(
        AlgorithmId::RsaesPkcs1V15,
        OperationMode::Decrypt,
        key_info.object_size(),
    ) {
        Err(e) => Err(e),
        Ok(cipher) => {
            cipher.set_key(&rsa.key)?;
            match cipher.decrypt(&mut [], &mut cipher_text) {
                Err(e) => Err(e),
                Ok(plain_text) => Ok(p1.buffer().clone_from_slice(&plain_text)),
            }
        }
    }
}