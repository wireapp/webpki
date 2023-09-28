use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use untrusted::Input;
use crate::{Error};

mod ed25519;
mod ecdsa;
mod rsa_pkcs;
mod rsa_pss;
pub mod alg;

pub use alg::*;

/// Same signature as the ring's 'VerificationAlgorithm' trait but we don't want to depend on this crate.
trait RustCryptoVerificationAlgorithm: Sync {
    /// Verify the signature `signature` of message `msg` with the public key `public_key`.
    fn verify(
        &self,
        public_key: Input,
        msg: Input,
        signature: Input,
    ) -> Result<(), Error>;
}

struct RustCryptoAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    verification_alg: &'static dyn RustCryptoVerificationAlgorithm,
}

impl SignatureVerificationAlgorithm for RustCryptoAlgorithm {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        self.verification_alg.verify(
            Input::from(public_key),
            Input::from(message),
            Input::from(signature),
        )
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}
