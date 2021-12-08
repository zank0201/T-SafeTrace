
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use optee_utee::{Random};
use proto::Command;


pub fn random_number_generate(params: &mut Parameters) -> Result<()> {
    let mut p = unsafe { params.0.as_memref().unwrap()};
    let mut buf = vec![0; p.buffer().len() as usize];
    buf.copy_from_slice(p.buffer());

    Random::generate(buf.as_mut() as _);
    p.buffer().copy_from_slice(&buf);

    Ok(())
}
