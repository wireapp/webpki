use untrusted::Input;
use crate::{
    error::Error,
    rust_crypto::RustCryptoVerificationAlgorithm,
};

pub(super) struct Ed25519;

impl RustCryptoVerificationAlgorithm for Ed25519 {
    fn verify(&self, public_key: Input, msg: Input, signature: Input) -> Result<(), Error> {
        let public_key = public_key.as_slice_less_safe().try_into().map_err(|_| Error::UnsupportedPublicKey)?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| Error::UnsupportedPublicKey)?;

        use ed25519_dalek::Verifier as _;
        let msg = msg.as_slice_less_safe();
        let signature = ed25519_dalek::Signature::from_slice(signature.as_slice_less_safe()).map_err(|_| Error::InvalidSignatureForPublicKey)?;
        public_key.verify(msg, &signature).map_err(|_| Error::InvalidSignatureForPublicKey)
    }
}