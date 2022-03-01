#![allow(unused_imports)]
#![allow(unused)]
use futures::{Future, Stream};
use std::sync::Arc;
use tokio_zmq::prelude::*;
use tokio_zmq::{Error, Multipart, Rep};
use zmq;
use optee_teec::{
    Context, Operation, ParamNone, ParamTmpRef, ParamType, ParamValue, Session, Uuid,
};

use crate::networking::messages::*;
use crate::networking::handling::*;
use crate::crypt::*;

// using https://github.com/scrtlabs/SafeTrace/blob/master/enclave/safetrace/app/src/networking/ipc_listener.rs
// implementation of IPC listener
type Result<T> = optee_teec::Result<T>;
pub struct EnclaveClient {
    pub uuid: String,
    pub context: optee_teec::Context,
}

impl EnclaveClient {
    pub fn open(uuid: &str) -> Result<Self> {
        Self::open_uuid(uuid)
    }

    fn open_uuid(uuid: &str) -> Result<Self> {
        let context = Context::new()?;
        Ok(Self {
            uuid: uuid.to_string(),
            context: context,
        })
    }
}
pub struct IpcListener {
    _context: Arc<zmq::Context>,
    rep_future: Box<dyn Future<Item = Rep, Error = Error>>,
}

impl IpcListener {
    pub fn new(conn_str: &str) -> Self {
        let _context = Arc::new(zmq::Context::new());
        let rep_future = Rep::builder(_context.clone()).bind(conn_str).build();
        println!("Binded to socket: {}", conn_str);
        IpcListener { _context, rep_future }
    }

    pub fn run<F>(self, f: F) -> impl Future<Item = (), Error = Error>
        where F: FnMut(Multipart) -> Multipart {
        self.rep_future.and_then(|rep| {
            let (sink, stream) = rep.sink_stream(25).split();
            stream.map(f).forward(sink).map(|(_stream, _sink)| ())
        })
    }
}

pub fn handle_message(request: Multipart, retries: u32, session: &mut Session) -> Multipart {
    let mut responses = Multipart::new();

    for msg in request {
        // let mut enclave = EnclaveClient::open(proto::UUID).unwrap();
        // let uuid_str = Uuid::parse_str(proto::UUID).unwrap();
        // let mut session = enclave.context.open_session(uuid_str).unwrap();
        //
        let msg: IpcMessageRequest = msg.into();
        let id = msg.id.clone();
        let response_msg = match msg.request {

            IpcRequest::GetEnclaveReport => get_ta_report(&mut *session),
            IpcRequest::NewTaskEncryptionKey {userPubKey}=> new_task_encryption_key(&mut *session, &userPubKey),
            IpcRequest::AddPersonalData { input } => add_personal_data(input, &mut *session),
            IpcRequest::FindMatch { input } => find_match(&mut *session, input),
            IpcRequest::getTotpKey {userPubKey} => generateTotp(&mut *session, &userPubKey),
        };
        println!("ipc request entered");
        let msg = IpcMessageResponse::from_response(response_msg.unwrap_or_error(), id);
        responses.push_back(msg.into());
        println!("push back mmsg");

    }
    responses
}