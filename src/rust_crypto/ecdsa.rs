use signature::Verifier;
use untrusted::Input;
use crate::{
    error::Error,
    rust_crypto::RustCryptoVerificationAlgorithm,
};
use der::Decode as _;

pub(super) struct EcdsaP256 {
    pub(super) digest_alg: pki_types::AlgorithmIdentifier,
}

impl RustCryptoVerificationAlgorithm for EcdsaP256 {
    fn verify(&self, public_key: Input, msg: Input, signature: Input) -> Result<(), Error> {
        let pk = public_key.as_slice_less_safe();
        let public_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| Error::UnsupportedPublicKey)?;

        let signature = signature.as_slice_less_safe();
        let signature = p256::ecdsa::Signature::from_der(signature).map_err(|_| Error::InvalidSignatureForPublicKey)?;

        let oid = const_oid::ObjectIdentifier::from_der(self.digest_alg.as_ref()).map_err(|_| Error::UnsupportedSignatureAlgorithm)?;

        let signature = ecdsa::SignatureWithOid::<p256::NistP256>::new(signature, oid).map_err(|_| Error::InvalidSignatureForPublicKey)?;

        let msg = msg.as_slice_less_safe();
        public_key.verify(msg, &signature).map_err(|_| Error::InvalidSignatureForPublicKey)
    }
}

pub(super) struct EcdsaP384 {
    pub(super) digest_alg: pki_types::AlgorithmIdentifier,
}

impl RustCryptoVerificationAlgorithm for EcdsaP384 {
    fn verify(&self, public_key: Input, msg: Input, signature: Input) -> Result<(), Error> {
        let pk = public_key.as_slice_less_safe();
        let public_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| Error::UnsupportedPublicKey)?;

        let msg = msg.as_slice_less_safe();
        let signature = signature.as_slice_less_safe();
        let signature = p384::ecdsa::Signature::from_der(signature).map_err(|_| Error::InvalidSignatureForPublicKey)?;

        let oid = const_oid::ObjectIdentifier::from_der(self.digest_alg.as_ref()).map_err(|_| Error::UnsupportedSignatureAlgorithm)?;

        let signature = ecdsa::SignatureWithOid::<p384::NistP384>::new(signature, oid).map_err(|_| Error::InvalidSignatureForPublicKey)?;

        public_key.verify(msg, &signature).map_err(|_| Error::InvalidSignatureForPublicKey)
    }
}
