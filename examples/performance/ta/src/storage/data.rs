#![no_std]

use optee_utee::{trace_println};
use optee_utee::{DataFlag, ObjectStorageConstants,PersistentObject, TransientObject, Whence};
use optee_utee::{Error, ErrorKind, Parameters,
                 Result};

use optee_utee::Time;

use crate::context::*;
use crate::crypto::authenticated::*;
use crate::storage::trusted_keys::*;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::str;
use serde_json::{Value, json};
use serde::{Deserialize, Serialize};



use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Write};

use std::process;
use rmp_serde::{Deserializer, Serializer};
// use serde::de::Error;
use serde_json::from_slice;

use rustc_hex::{FromHex, ToHex};
use crate::storage::{trusted_keys::KeyStorage};
const TEST_OBJECT_SIZE: usize = 7000;
const STORAGE_ID: &str = "Performance";
const TA_KEY: &str = "DataKey";
pub const TOVERLAP: i32 = 300;             // 5min * 60s minimum overlap
pub const DISTANCE: f64 = 10.0;            // in meters
pub const EARTH_RADIUS: f64 = 6371000.0;   // in meters
// .unwrap().into_bytes_with_nul()
///DHKEYs data

const ERR_DEFAULT: &str = "error message";
/// creates new object
/// we can overwrite obj data if the obj id exists using the data flag
/// @params: obj_id= user id from client
/// @params: keypair from ecdsa
// Add match mode to either use private
// data stored in clear text
//TODO change create to poverwrite data
pub fn create_raw_object(signing_key: &mut KeyStorage, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    // let mut p1 = unsafe { params.1.as_memref().unwrap() };
    //
    delete_object()?;


    signing_key.get_key_object()?;
    let signing_clone = &signing_key.access_field().clone();

   p0.buffer().clone_from_slice(&signing_clone);
    let obj_id = CString::new(STORAGE_ID).unwrap().into_bytes_with_nul();
    // let mut obj_data = [0u8; TEST_OBJECT_SIZE];
    // obj_id.copy_from_slice(p0.buffer());
    // let mut data_buffer = vec![0; p1.buffer().len() as usize];
    // data_buffer.copy_from_slice(p1.buffer());
    let mut status = false;

    //TODO needs c representation

    let mut data_array: BTreeMap<String, Vec<Geolocation>> = BTreeMap::new();
    let mut encoded_slice = encode_data(data_array).unwrap();
    //call keypair

    let mut encrypt_tree = Cipher::encrypt(&mut encoded_slice,&mut signing_key.access_field()).unwrap();

    // need key from
    // trace_println!("[+] create_raw_object");
    let obj_data_flag = DataFlag::SHARE_READ
        | DataFlag::ACCESS_WRITE
        | DataFlag::SHARE_WRITE;

    let mut init_data: [u8; 0] = [0; 0];

    match PersistentObject::create(
        ObjectStorageConstants::Private,
        &obj_id,
        obj_data_flag,
        None,
        &mut encrypt_tree,
    ) {
        Err(e) => {
            if e.kind() == ErrorKind::AccessConflict{
               Ok(())
            }else{
            trace_println!("{}", e);
            return Err(e)}
        }

        Ok(_object) => {
            // object.write(&encrypt_tree);
            return Ok(())
        }


    }
}

pub fn write_to_storage(data:&[u8]) -> Result<()> {
   // trace_println!("[+] entered write storage");
    // let obj_data = hashmap_population(ptr,string_id, input_data);
    // (string_id, input_data);

    let mut obj_id = CString::new(STORAGE_ID).unwrap().into_bytes_with_nul();

    match PersistentObject::open (
        ObjectStorageConstants::Private,
        &mut obj_id,
        DataFlag::ACCESS_WRITE | DataFlag::ACCESS_WRITE
            | DataFlag::ACCESS_WRITE_META| DataFlag::SHARE_READ |
            DataFlag::SHARE_WRITE) {
        Ok(mut object) => {
            // trace_println!("[+] write storage to stroage");
            object.write(&data)?;


            // object.seek(0i32, Whence::DataSeekCur)?;
            Ok(())

        },
        Err(e) => return Err(e)
    }


}

pub fn delete_object() -> Result<()> {
    let mut obj_id = CString::new(STORAGE_ID).unwrap().into_bytes_with_nul();


    match PersistentObject::open(
        ObjectStorageConstants::Private,
        &mut obj_id,
        DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE_META,
    ) {
        Err(e) => {
            return Err(e);
        }

        Ok(mut object) => {
            object.close_and_delete()?;
            std::mem::forget(object);
            return Ok(());
        }
    }
}

// find obj

pub fn read_raw_object() -> Result<Vec<u8>> {
    let mut obj_id = CString::new(STORAGE_ID).unwrap().into_bytes_with_nul();
    // let mut p0 = unsafe { params.0.as_memref().unwrap() };
    // let mut p1 = unsafe { params.1.as_memref().unwrap() };
    //
    // let mut obj_id = vec![0; p1.buffer().len() as usize];
    // obj_id.copy_from_slice(p1.buffer());
    //
    // let mut data_buffer = vec![0;p0.buffer().len() as usize];
    // data_buffer.copy_from_slice(p0.buffer());




    match PersistentObject::open(
        ObjectStorageConstants::Private,
        &mut obj_id,
        DataFlag::ACCESS_READ | DataFlag::SHARE_READ,
    ) {

        Err(e) => {
            trace_println!("read error {}", e);

            return Err(e)},

        Ok(object) => {
            let obj_info = object.info()?;

            let mut data_buffer = vec![0u8; obj_info.data_size() as usize];
            let read_bytes = object.read(&mut data_buffer).unwrap();
            if read_bytes != obj_info.data_size() as u32 {
                return Err(Error::new(ErrorKind::ExcessData));
            }





            // trace_println!("done reading");

            return Ok(data_buffer)
        }
    }
}

///#Params:
/// p0 = status
/// p1 = user id
/// p2 = key
/// p3 = data
/// hashmap
///
///
pub fn add_data_object(storage_key: &mut KeyStorage, params: &mut Parameters) -> Result<()> {
    // delete_object()?;
    // storage_encryption_key()?;

//start time time stamp

    // let mut start_time = Time::new();
    // start_time.system_time();
    // trace_println!("start time {}", start_time);
    let mut p0 = unsafe { params.0.as_value().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    let mut p3 = unsafe { params.3.as_memref().unwrap() };
    let mut user_id = vec![0; p1.buffer().len() as usize];

    let mut buffer = p2.buffer();
    user_id.copy_from_slice(p1.buffer());

    let (mut user_pub, mut sign) = buffer.split_at_mut(buffer.len()/2);

    // user_pub.clone_from_slice(&buffer[..64]);
    // sign.clone_from_slice(&buffer[64..]);


    // let pub_array = vector_array(&user_pub);
    // let map_enum = ta_keygen::DH_KEYS.lock().unwrap();
    // for (key, val) in map_enum.iter() {
    //         trace_println!("key: {:?}", key);
    //         trace_println!("val: {:?}", val);
    //     }

    nistp256::verify(sign,user_pub)?;


    // trace_println!("end time {}", end_time);


    let io_key;
    match remove_io_key(user_pub) {
        Ok(v) => io_key = v,
        Err(e) => return Err(e),
    };
    // let key =  match get_io_key(user_pub) {
    //     Ok(v) =>
    // };




    let mut obj_id = CString::new(STORAGE_ID).unwrap().into_bytes_with_nul();

    // println!("from tee");
    // let mut decrypted_obj_id = find_match_optee(&mut obj_id, key).unwrap();

    let mut data_buffer = vec![0;p3.buffer().len() as usize];
    data_buffer.copy_from_slice(p3.buffer());



    let decrypted_user_id = Cipher::decrypt(&mut user_id, &io_key).unwrap();

    trace_println!("exit user id");
    let decrypted_data = Cipher::decrypt(&mut data_buffer, &io_key).unwrap();
    // let (decrypted_user_id, decrypted_data) = decrypt_new_user(&mut user_id, &mut data_buffer, &key).unwrap();

    trace_println!("exit data");
    let string_id = str::from_utf8(&decrypted_user_id).unwrap();

    //
    // let string_data = String::from_utf8(decrypted_data);

    let mut input_data = serde_json::from_slice(&decrypted_data).unwrap();

    // let mut init_data: [u8; 0] = [0; 0];
    // let mut new_output = read_raw_object().unwrap();
    // trace_println!("we left output buffer {:?}", new_output.len());
    // let mut start_time = Time::new();
    // start_time.system_time();
    let obj_data_flag =
        DataFlag::ACCESS_WRITE|
            DataFlag::SHARE_WRITE
        | DataFlag::ACCESS_READ | DataFlag::SHARE_READ;

    match PersistentObject::open(
        ObjectStorageConstants::Private,
        &mut obj_id,
        obj_data_flag,
    ) {
        //TODO use if statememnt to create or read data
        // Then create hashmap or in function or ourside
        Err(e) =>
            {
                trace_println!("entered add data {:?}", e);


                return Err(e)},
        // [235, 209, 56, 136, 81, 104, 123, 104, 179, 19, 153, 135, 94, 222, 17, 239, 5, 30, 115, 222, 195, 200, 213, 132, 7, 193, 60, 71, 232, 105, 40, 216, 42, 66, 27, 212, 80, 5, 11, 58, 145, 234, 44]



        Ok(mut object) => {
            let obj_info = object.info()?;

            let mut storage_buffer = vec![0u8; obj_info.data_size() as usize];

            let read_bytes = object.read(&mut storage_buffer).unwrap();


            // trace_println!("read bytes {}", read_bytes);
            if read_bytes != obj_info.data_size() as u32 {
                return Err(Error::new(ErrorKind::ExcessData));
            }



            let mut tmp = Cipher::decrypt(&mut storage_buffer, &storage_key.access_field() ).unwrap();

            // trace_println!("storage data {}", storage_buffer.len());
            let mut data_bytes: BTreeMap<String, Vec<Geolocation>> = serde_json::from_slice(&tmp).unwrap();

            // trace_println!("[+] serialize from storage {:?}", &keys);
            // let keys: Vec<_> = data_bytes.keys().cloned().collect();
            data_bytes.insert(string_id.to_string(), input_data);

            let mut encoded_slice = encode_data(data_bytes).unwrap();

            let mut encrypt_tree = Cipher::encrypt(&mut encoded_slice,&mut storage_key.access_field()).unwrap();


            object.seek(0i32, Whence::DataSeekSet)?;
            // trace_println!("encrypt buffer {}", &encrypt_tree.len());
            object.write(&encrypt_tree)?;
            // write_to_storage(&encoded_slice)?;


            // let mut end_time = Time::new();
            // end_time.system_time();
            // // trace_println!("end time {}", end_time);
            //
            // let delta_time = get_response_time(start_time, end_time).unwrap();
            // trace_println!("delta time {}", delta_time);


           // let data_stamp = write_to_file(delta_time, encrypt_tree.len() as u32).unwrap();
            // trace_println!("data stamp {:?}", data_stamp);
            //
            //
            // let data_buffer_encrypt = match_encrypt(&mut data_buffer, key).unwrap();
            // object.seek(0, Whence::DataSeekCur)?;
            // trace_println!("done reading");


            // let str_r = u32::from_str_radix(&data_stamp, 32).unwrap();
            // p0.set_a(delta_time);
            // p0.set_b(encrypt_tree.len() as u32);


            Ok(())
        }
    }
}
pub fn find_match_optee(storage_key: &mut KeyStorage, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    let mut user_id = vec![0; p0.buffer().len() as usize];
    user_id.copy_from_slice(p0.buffer());
    let user_pub = p1.buffer();
    // let pub_array = vector_array(&user_pub);
    // trace_println!("io string {:?}", &user_pub);
    let io_key;
    match remove_io_key(user_pub) {
        Ok(v) => io_key = v,
        Err(e) => return Err(e),
    };

    let decrypted_user_id = Cipher::decrypt(&mut user_id, &io_key).unwrap();
    let string_id = str::from_utf8(&decrypted_user_id).unwrap();

    let mut read_bytes = read_raw_object().unwrap();
    let mut tmp = Cipher::decrypt(&mut read_bytes, &storage_key.access_field() ).unwrap();



    let mut data_bytes: BTreeMap<String, Vec<Geolocation>> = serde_json::from_slice(&tmp).unwrap();


    let mut results = Vec::new();
    for (key, val) in data_bytes.iter() {
        if key != &string_id {

            for d in data_bytes[string_id].clone() {

                for e in val.iter() {
                    if e.testResult {
                        // It's easier to find overlaps in time because it's a direct comparison of integers
                        // so handle this first:
                        // Both time intervals have to be larger than the minumum time overlap TOVERLAP
                        // and both start times + TOVERLAP have to be smaller than the other end times
                        if d.endTS - d.startTS > TOVERLAP &&
                            e.endTS - e.startTS > TOVERLAP &&
                            d.startTS + TOVERLAP < e.endTS && e.startTS + TOVERLAP < d.endTS {
                            // We start comparing distance between latitudes. Each degree of lat is aprox
                            // 111 kms (range varies between 110.567 km at the equator to 111.699 km at the poles)
                            // The distance between two locations will be equal or larger than the distance between
                            // their latitudes (or the distance between lats will be smaller than the distance * cos(45))
                            // Source:
                            // https://stackoverflow.com/questions/5031268/algorithm-to-find-all-latitude-longitude-locations-within-a-certain-distance-fro
                            if (e.lat - d.lat).abs() * 111000.0 <  DISTANCE * 0.71 {
                                // then we can run a more computationally expensive and precise comparison
                                // if ((e.lat).sin()*(d.lat).sin()+e.lat.cos()*d.lat.cos()*(e.lng-d.lng).cos()).acos() * EARTH_RADIUS < DISTANCE {
                                //     results.push(d.clone());
                                if libm::acos(libm::sin(e.lat)*libm::sin(d.lat)+libm::cos(e.lat)*libm::cos(d.lat)*libm::cos(e.lng-d.lng)) * EARTH_RADIUS < DISTANCE {
                                    // trace_println!("results pushed?");
                                    results.push(d.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut serialized_results = serde_json::to_string(&results).expect("serialized_results");
    let mut array_u8_results = serialized_results.as_bytes();
    let encrypted_output = Cipher::encrypt(&mut array_u8_results.to_vec(), &io_key).unwrap();

    p2.buffer().copy_from_slice(&encrypted_output);

    Ok(())

}
pub fn remove_io_key(user_pub: &mut [u8]) -> Result<DHKey> {
    // let user_clone = user_pub.clone();

    let user_array = user_pub.to_hex();
    let mut io_key = ta_keygen::DH_KEYS.lock().expect("User dh key")
        .remove(user_array.as_str()).unwrap();

        // let io_clone = io_key.ok_or(ERR_DEFAULT).expect("user pubkey");

    Ok(io_key)
}
pub fn get_io_key(user_pub: &mut [u8]) -> Result<Vec<u8>> {
    // let user_clone = user_pub.clone();
    let user_array = user_pub.to_hex();
    let mut io_key = ta_keygen::DH_KEYS.lock().expect("User dh key");
    let io_clone = io_key.get(user_array.as_str()).unwrap();

    // let io_clone = io_key.ok_or(ERR_DEFAULT).expect("user pubkey");

    Ok(io_clone.to_vec())
}
fn encode_data(data: BTreeMap<String, Vec<Geolocation>>) -> Result<Vec<u8>> {
    let encoded_vec = serde_json::to_vec(&data).unwrap();

    Ok(encoded_vec)
}
///function converting time to milliseconds
fn time_in_ms(t: Time) -> Result<u32> {
    Ok(t.seconds * 1000 + t.millis)
}

/// function to get delta time in ms
pub fn get_response_time(startTime: Time, stopTime: Time) -> Result<u32> {

    let response_value = time_in_ms(stopTime).unwrap() - time_in_ms(startTime).unwrap();
    Ok(response_value)
}


// fn write_to_file(time: u32, bytes_val: u32) -> Result<Vec<(u32, u32>> {
//
//     let data = vec![time.to_string(), bytes_val.to_string()];
//     let data_joined = data.join(",");
//
//     // let data_txt = format!("{}{}", data_joined, "\n");
//



    // trace_println!("string converted");
    // wrt.serialize(Record {
    //     responseTime: time.to_string(),
    //     bytes: bytes_val.to_string(),
    // }).unwrap();
    // trace_println!("seriliaze error");


    // write!(file,"{}", data_txt).unwrap();
//
//     Ok(data)
// }