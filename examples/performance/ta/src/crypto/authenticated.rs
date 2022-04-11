use optee_utee::{
    trace_println,
};
use serde_json::{Value, json};
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};
use optee_utee::{AlgorithmId, OperationMode, AE};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, Mode, BUFFER_SIZE, K_LEN, TAG_LEN, AAD_LEN};
pub use crate::crypto::*;
pub use crate::crypto::context::*;
use crate::storage::data::*;
use std::collections::HashMap;

/// params:
/// p0 = mode
/// p1 = src
/// p2 = key
/// p3 = res=ciph
#[derive(Clone, Default, Debug)]
pub struct Cipher {
    pub text: Vec<u8>,
    pub tag: Vec<u8>,
    pub nonce: Vec<u8>,

}
impl Cipher {
    pub fn data_split(data_values: Vec<u8>) -> Result<Cipher> {
        let (mut ciph, nonce) = data_values.split_at(&data_values.len() - 12);
        let (mut ciph_update, mut tag) = ciph.split_at(ciph.len() - 16);
        return Ok(Cipher { text: ciph_update.to_vec(), tag: tag.to_vec(), nonce: nonce.to_vec() })
    }
    pub fn encrypt(decrypted_data: &mut [u8], key: &[u8]) -> Result<Vec<u8>> {
        let mut ae = context::NewOperations::default();
        // let aad = [0u8; AAD_LEN];
        let mut tmp = vec![0u8; decrypted_data.len() as usize];

        let mut tag_buffer = [0u8; TAG_LEN as usize];
        let nonce = randomGen::random_number_generate().unwrap();
        ae.AeOp = AE::allocate(AlgorithmId::AesGcm, OperationMode::Encrypt, K_LEN * 8).unwrap();

        match TransientObject::allocate(TransientObjectType::Aes, K_LEN * 8) {
            Err(e) => { return Err(e) },
            Ok(mut key_object) => {
                let attr = AttributeMemref::from_ref(AttributeId::SecretValue, key);
                key_object.populate(&[attr.into()])?;
                ae.AeOp.set_key(&key_object)?;
                ae.AeOp.init(&nonce, TAG_LEN * 8, 0, 0)?;
                // ae.AeOp.update_aad(&aad);


                let mut clear = vec![0; decrypted_data.len() as usize];
                clear.copy_from_slice(&decrypted_data);

                let mut ciph = vec![0; decrypted_data.len() as usize];
                // ciph.copy_from_slice(&tmp);

                // let mut tag_encrypt = vec![0; tag_buffer.len() as usize];
                // tag_encrypt.copy_from_slice(&tag_buffer);
                match ae.AeOp.encrypt_final(&clear, &mut ciph, &mut tag_buffer) {
                    Err(e) =>{
                        trace_println!("encryption error: {}",e );
                        return Err(e)},
                    Ok((_ciph_len, _tag_len)) => {
                        decrypted_data.copy_from_slice(&clear);
                        tmp.copy_from_slice(&ciph);

                        // tag_buffer.copy_from_slice(&tag);
                        tmp.extend(tag_buffer);
                        tmp.extend(nonce);
                    }
                }

                Ok(tmp)
            }
        }
    }
    pub fn decrypt(encrypt_data: &mut [u8], key: &[u8]) -> Result<Vec<u8>> {
        let mut ae = context::NewOperations::default();
        let aad = [0u8; AAD_LEN];
        let data = Cipher::data_split(encrypt_data.to_vec()).unwrap();
        ae.AeOp = AE::allocate(AlgorithmId::AesGcm, OperationMode::Decrypt, K_LEN * 8).unwrap();

        let mut ciph = vec![0u8; data.text.len()];
        match TransientObject::allocate(TransientObjectType::Aes, K_LEN * 8) {
            Err(e) => {
                trace_println!("decryption error: {}", e);
                return Err(e) },
            Ok(mut key_object) => {
                let attr = AttributeMemref::from_ref(AttributeId::SecretValue, key);
                key_object.populate(&[attr.into()])?;
                ae.AeOp.set_key(&key_object)?;
                ae.AeOp.init(&data.nonce, TAG_LEN * 8, 0, 0)?;
                // ae.AeOp.update_aad(&aad);

                match ae.AeOp.decrypt_final(&data.text, &mut ciph, &data.tag) {
                    Err(e) => {
                        trace_println!("decryption error: {}", e);
                        return Err(e)
                    },
                    Ok(_ciph_len) => {
                        // input.copy_from_slice(&clear);
                        // tmp.copy_from_slice(&ciph);
                        //
                        // tag.copy_from_slice(&id_tag_buffer);
                        // status = true;

                    }
                }
                Ok(ciph)
            }
        }
    }
}


