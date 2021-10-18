/// create struct with parameters k, v, count

use optee_utee::{AlgorithmId, Mac, Digest, Asymmetric, OperationMode};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
// since I know what size v and k , we dont need to use generic arrays
pub struct HmacDrbg {
    pub k: [u8;32],
    pub v: [u8;32],
    pub count: usize,
    pub key: TransientObject,
    pub op: Mac,
}
pub struct Hmac {
    pub key: TransientObject,
    pub op: Mac,
}

impl Default for Hmac {
    fn default() -> Self {
        Self {
            key: TransientObject::null_object(),
            op: Mac::null(),
        }
    }
}


impl Default for HmacDrbg {
    fn default() -> Self {
        Self {
            k: [0u8; 32],
            v: [0u8; 32],
            count: 0,
            key: TransientObject::null_object(),
            op: Mac::null(),
        }
    }
}
impl HmacDrbg {
    pub fn new(key: &[u8], nonce: &[u8], pers: &[u8]) -> Self {
        for i in 0..k.len() {
            k[i] = 0x0;
        }
        for i in 0..v.len() {
            v[i] = 0x01;
        }
        let mut this = Self {k,v, count, key, op};
        this.hmac_update(Some(&[key, nonce, pers]));
        this.count = 1;
        this

    }
    pub fn count(&self) -> usize {
        self.count
    }

    /// hmaac funtion to initialise the hash
    pub fn hmac_init(&self) -> Result<()>{
        &self.op = Mac::allocate(AlgorithmId::HmacSha256, 256);
        &self.key = TransientObject::allocate(TransientObjectType::HmacSha256, 256);
        let mut tmp_key = self.k.to_vec();
        tmp_key.truncate(32);
        let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &tmp_key);
        &self.key
            .populate(&[attr.into()])?;
        &self.op
            .set_key(&hmac.key);
        &self.op.init(&[0u8; 0]);
        Ok(())
    }

   pub fn hmac_update(&self, seeds:Option<&[&[u8]]>, hmac: &mut Hmac) -> Result<()> {
       self.hmac_init();
       &self.op.update(&self.v);
       &self.op.update(&[0x00]);
       if let Some(seeds) = seeds {
           for seed in seeds {
               &self.op.update(seed);
           }
       }
       self.k = self.op.compute_final(&[0u8;0]).unwrap().into_bytes();
       Ok(())

    }

}