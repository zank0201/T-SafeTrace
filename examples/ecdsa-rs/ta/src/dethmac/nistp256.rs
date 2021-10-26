use optee_utee::{TransientObject, TransientObjectType, AlgorithmId, ElementId, Asymmetric, Digest};

// struct containing public key and secret key

pub struct Ecdsa {
    pub key: TransientObject,
    pub op: Asymmetric,
    pub digestop: Digest,


}

impl Default for Ecdsa {
    fn default() -> Self {
        Self {
            key: TransientObject::null_object(),
            op: Asymmetric::null(),
            digestop: Digest::allocate(AlgorithmId::Sha256).unwrap(),

        }
    }
}

