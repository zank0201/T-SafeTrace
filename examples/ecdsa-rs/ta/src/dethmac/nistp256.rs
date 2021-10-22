use optee_utee::{TransientObject, TransientObjectType, ElementId, Asymmetric};
pub use {
    p256::{AffinePoint, ProjectivePoint, Scalar},
    core::borrow::Borrow,
    ecdsa::hazmat::{SignPrimitive, VerifyPrimitive},
    elliptic_curve::{
        group::ff::Field,
        ops::{Invert},
    },
};

// struct containing public key and secret key
pub struct SecretKeys {
    pub privatekey: Scalar,
    pub public_y: Scalar,
    pub public_x: Scalar,
}
pub struct Ecdsa {
    pub key: TransientObject,
    pub op: Asymmetric,


}

impl Default for Ecdsa {
    fn default() -> Self {
        Self {
            key: TransientObject::null_object(),
            op: Asymmetric::null(),

        }
    }
}

