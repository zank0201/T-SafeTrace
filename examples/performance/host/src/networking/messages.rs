#![allow(unused_imports)]
use serde_json;
use serde_repr::{Serialize_repr, Deserialize_repr};
use zmq::Message;
use serde::{Deserialize, Serialize};
use log::error;
use rustc_hex::{FromHex, ToHex};
// These attributes enable the status to be casted as an i8 object as well
pub const PREFIX: &'static [u8; 27] = b"Trusted Application Message";

#[derive(Serialize_repr, Deserialize_repr, Clone, Debug)]
#[repr(i8)]
pub enum Status {
    Failed = -1,
    Passed = 0,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keypair {
    pub pubkeyX: String,
    pub pubkeyY: String,
    // private_key: String,
}

impl Keypair {
    pub fn hex_keypair(&self) -> String
    {
        // let public_x = ecc_x.to_hex();
        // let public_y = ecc_y.to_hex();
        // let hex_private = private_key.to_hex();
        let owned_pubx: String = self.pubkeyX.to_owned();
        let borrowed_puby: &str = &self.pubkeyY;
        owned_pubx.clone() + borrowed_puby

        // self.private_key = private_key.to_hex();
    }

    // pub fn derive_public_pair(publickey: String) -> (Vec<u8>, Vec<u8>) {
    //     let ecc_x,
    // }

}
#[derive(Deserialize, Debug)]
pub struct TaResponse {
    shared_secret: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessageRequest {
    pub id: String,
    #[serde(flatten)]
    pub request: IpcRequest
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcStatusResult {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<i64>,
    pub status: Status,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessageResponse {
    pub id: String,
    #[serde(flatten)]
    pub response: IpcResponse
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetEnclaveReport { #[serde(flatten)] result: IpcResults },
    NewTaskEncryptionKey { #[serde(flatten)] result: IpcResults },
    getTotpKey{#[serde(flatten)] result: IpcResults },
    AddPersonalData { #[serde(flatten)] result: IpcResults },
    FindMatch { #[serde(flatten)] result: IpcResults },
    Error { msg: String },
}
// needs renaming
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", rename = "result")]
pub enum IpcResults {
    Errors(Vec<IpcStatusResult>),
    #[serde(rename = "result")]
    Request { request: String, sig: String },
    #[serde(rename = "result")]
    EnclaveReport { #[serde(rename = "signingKey")] signing_key: String},
    #[serde(rename = "result")]
    DHKey { taskPubKey: String, sig: String },
    AddPersonalData { status: Status },
    #[serde(rename = "result")]
    Totp {token: String},
    FindMatch { status: Status, #[serde(skip_serializing_if = "String::is_empty")] encryptedOutput: String },
}


#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcRequest {
    GetEnclaveReport,
    NewTaskEncryptionKey { userPubKey: String },
    AddPersonalData { input: IpcInputData },
    FindMatch { input: IpcInputMatch },
    getTotpKey{userPubKey: String}

}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcInputData {
    #[serde(rename = "encryptedUserId")] pub encrypted_userid: String,
    #[serde(rename = "encryptedData")] pub encrypted_data: String,
    #[serde(rename = "userPubKey")] pub user_pub_key: String,
    #[serde(rename = "taskSign")] pub user_sig: String,


}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcInputMatch {
    #[serde(rename = "encryptedUserId")] pub encrypted_userid: String,
    #[serde(rename = "userPubKey")] pub user_pub_key: String,
}

impl IpcMessageResponse {
    pub fn from_response(response: IpcResponse, id: String) -> Self {
        Self { id, response }
    }
}
impl IpcMessageRequest {
    pub fn from_request(request: IpcRequest, id: String) -> Self {
        Self { id, request }
    }
}

impl From<Message> for IpcMessageRequest {
    fn from(msg: Message) -> Self {
        let msg_str = msg.as_str().unwrap();
        let req: Self = serde_json::from_str(msg_str).expect(msg_str);
        req
    }
}

impl Into<Message> for IpcMessageResponse {
    fn into(self) -> Message {
        let msg = serde_json::to_vec(&self).unwrap();
        Message::from(&msg)
    }
}
pub(crate) trait UnwrapError<T> {
    fn unwrap_or_error(self) -> T;
}

impl<E: std::fmt::Display> UnwrapError<IpcResponse> for Result<IpcResponse, E> {
    fn unwrap_or_error(self) -> IpcResponse {
        match self {
            Ok(m) => m,
            Err(e) => {
                error!("Unwrapped Message failed: {}", e);
                IpcResponse::Error {msg: format!("{}", e)}
            }
        }
    }
}
