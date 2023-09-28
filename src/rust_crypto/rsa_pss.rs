use der::{Decode};
use rsa::{BigUint, sha2};
use untrusted::Input;
use crate::{error::Error, rust_crypto::RustCryptoVerificationAlgorithm, alg_id};

pub(super) struct RsaPss {
    pub(super) alg: pki_types::AlgorithmIdentifier,
    pub(super) n_min_bits: usize,
    pub(super) n_max_bits: usize,
}

impl RustCryptoVerificationAlgorithm for RsaPss {
    fn verify(&self, public_key: Input, msg: Input, signature: Input) -> Result<(), Error> {
        let pk = public_key.as_slice_less_safe();
        let msg = msg.as_slice_less_safe();

        let vk = rsa::pkcs1::RsaPublicKey::from_der(pk).map_err(|_| Error::UnsupportedPublicKey)?;

        let n = BigUint::from_bytes_be(vk.modulus.as_bytes());
        let n_size = n.bits();
        if n_size < self.n_min_bits || n_size > self.n_max_bits {
            return Err(Error::UnsupportedPublicKey);
        }

        let e = BigUint::from_bytes_be(vk.public_exponent.as_bytes());
        let key = rsa::RsaPublicKey::new(n, e).map_err(|_| Error::UnsupportedPublicKey)?;

        let signature = rsa::pss::Signature::try_from(signature.as_slice_less_safe()).map_err(|_| Error::InvalidSignatureForPublicKey)?;

        use signature::Verifier as _;
        if self.alg == alg_id::RSA_PSS_SHA256 {
            let vk = rsa::pss::VerifyingKey::<sha2::Sha256>::new(key);
            vk.verify(msg, &signature)
        } else if self.alg == alg_id::RSA_PSS_SHA384 {
            let vk = rsa::pss::VerifyingKey::<sha2::Sha384>::new(key);
            vk.verify(msg, &signature)
        } else if self.alg == alg_id::RSA_PSS_SHA512 {
            let vk = rsa::pss::VerifyingKey::<sha2::Sha512>::new(key);
            vk.verify(msg, &signature)
        } else {
            return Err(Error::UnsupportedSignatureAlgorithm);
        }.map_err(|_| Error::InvalidSignatureForPublicKey)
    }
}