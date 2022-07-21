use optee_utee::{
    trace_println,
};
use optee_utee::{AlgorithmId, OperationMode, AE, DataFlag, ObjectStorageConstants,PersistentObject, TransientObject, Whence};
use optee_utee::{AttributeId, AttributeMemref, AttributeValue, ElementId,TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, KEY_SIZE, K_LEN};
pub use crate::crypto::context::*;
const TA_KEY: &str = "DataKey";
const STORAGE_ID: &str = "Storage";
use std::ffi::CString;
use std::str;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
// generate new keypair
//run this function to create the persistent obj
// then read from data storage everytime wwe need it

#[derive(Debug)]
pub struct KeyStorage {
    pub data: Vec<u8>,
    // pub user_pub: Vec<u8>,
    // pub derived_key: Vec<u8>,
    // // pub map: BTreeMap<Vec<u8>, DHKey>,
}
impl Default for KeyStorage {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            // user_pub: Vec::new(),
            // derived_key: Vec::new(),
            // map: BTreeMap::new(),
        }
        }
    }
impl KeyStorage {
    pub fn get_key_object(&mut self) -> Result<()>{
        storage_encryption_key()?;
        // trace_println!("entered function get object");
        let mut obj_id = CString::new(TA_KEY).unwrap().into_bytes_with_nul();

        let mut data_buffer = vec![0;K_LEN as usize];





        match PersistentObject::open(
            ObjectStorageConstants::Private,
            &mut obj_id,
            DataFlag::ACCESS_READ | DataFlag::SHARE_READ,
        ) {

            Err(e) =>{
                trace_println!("get object key {}", e);
                return Err(e)},

            Ok(object) => {
                let obj_info = object.info()?;

                if obj_info.data_size() > data_buffer.len() {
                    return Err(Error::new(ErrorKind::ShortBuffer));
                }
                let read_bytes = object.read(&mut data_buffer).unwrap();
                if read_bytes != obj_info.data_size() as u32 {
                    return Err(Error::new(ErrorKind::ExcessData));
                }






                // trace_println!("done reading");
                self.data = data_buffer;
                Ok(())
            }
        }
    }
    pub fn access_field(&mut self) -> Vec<u8> {
        self.data.to_vec()
    }

    // pub fn new() -> Result<()> {
    //     let DH_keys:  Mutex<BTreeMap<Vec<u8>, DHKey>> = Mutex::new(BTreeMap::new());
    //     Ok(())
    // }
//     pub fn insert_keys(&mut self, userpub: Vec<u8>, derived_key: Vec<u8>) -> Result<()> {
//         self.map = self.map.insert(userpub, derived_key).unwrap();
//
//         // for (key, val) in map_enum.iter() {
//         //     trace_println!("key: {:?}", key);
//         //     trace_println!("val: {:?}", val);
//         // }
//         Ok(())
//     }
//     pub fn remove_keys(&mut self, user_pub: &mut [u8]) -> Result<DHKey> {
//         trace_println!("entered remove key {:?}", &user_pub);
//         let mut io_key = self.map.remove(&user_pub.to_vec());
//
//         trace_println!("io key {:?}", &io_key);
//         Ok(io_key.unwrap())
//     }
}

pub fn new_keypair() -> Result<Vec<u8>> {
    let mut key = NewOperations::default();
    key.ecdh_keypair = TransientObject::allocate(TransientObjectType::EcdhKeypair, KEY_SIZE).unwrap();
    let attr_ecc = AttributeValue::from_value(AttributeId::EccCurve, ElementId::EccCurveNistP256 as u32, 0);
    let mut private_buffer = [0u8;32];
    key.ecdh_keypair
        .generate_key(KEY_SIZE, &[attr_ecc.into()])?;
    let mut private_key_size = key.ecdh_keypair
        .ref_attribute(AttributeId::EccPrivateValue, &mut private_buffer)
        .unwrap();
    let mut private_res = vec![0u8; private_key_size as usize];
    private_res.copy_from_slice(&private_buffer[..private_key_size as usize]);
    // trace_println!("Done generating");
    return Ok(private_res)

}
pub fn storage_encryption_key() -> Result<()> {
    let mut obj_id = CString::new(TA_KEY).unwrap().into_bytes_with_nul();
    let obj_data = new_keypair().unwrap();
    let obj_data_flag = DataFlag::ACCESS_READ
        | DataFlag::ACCESS_WRITE
        | DataFlag::ACCESS_WRITE_META |
        DataFlag::OVERWRITE;

    let mut init_data: [u8; 0] = [0; 0];

    match PersistentObject::create(
        ObjectStorageConstants::Private,
        &mut obj_id,
        obj_data_flag,
        None,
        &mut init_data,
    ) {
        Err(e) => {
            trace_println!("{}", e);
            return Err(e);
        }

        Ok(mut object) => match object.write(&obj_data) {
            Ok(()) => {
                return Ok(());
            }
            Err(e_write) => {
                object.close_and_delete()?;
                std::mem::forget(object);
                return Err(e_write);
            }
        },
    }
}

