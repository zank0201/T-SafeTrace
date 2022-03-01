use optee_utee::{
    trace_println,
};
use serde_json::{Value, json};
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};
use optee_utee::{AlgorithmId, OperationMode, AE};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, Mode, BUFFER_SIZE, K_LEN, TAG_LEN};
pub use crate::crypto::*;
pub use crate::crypto::context::*;
use crate::storage::data::*;
use std::collections::HashMap;
//
// pub fn encrypt_storage() -> Result<()> {
//
// }