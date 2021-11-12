use optee_teec::{Context, Operation, Session, Uuid};
use optee_teec::ParamNone;
use proto::{Command,AAD_LEN, BUFFER_SIZE, KEY_SIZE, UUID};
use std::sync::Arc;

// use futures::{Future, Stream};
// use tokio_zmq::{prelude::*, Rep};
// pub async fn tcp_client() {
//     println!("hello from async");
//     let _socket = TcpStream::connect("127.0.0.1:3000").await.unwrap();
//     println!("async TCP operation complete");
// }
