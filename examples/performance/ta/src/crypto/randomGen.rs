
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{Random};
use proto::Command;


pub fn random_number_generate() -> Result<Vec<u8>> {
    // let mut p = unsafe { params.0.as_memref().unwrap()};
    // let mut buf = vec![0; p.buffer().len() as usize];
    // buf.copy_from_slice(p.buffer());

    let mut buffer = [0u8;12];

    Random::generate(buffer.as_mut() as _);
    // p.buffer().copy_from_slice(&buf);

    Ok(buffer.to_vec())
}
