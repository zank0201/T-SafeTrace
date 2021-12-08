use optee_utee::{trace_println};

use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::net::TcpStream;
//note secure world = 54321
pub fn tcp_client() -> Result<()> {
    trace_println!("we have entered function");
    let mut stream = TcpStream::connect("127.0.0.1", 8080).unwrap();
    trace_println!("we have connected stream");
    Ok(())

}
