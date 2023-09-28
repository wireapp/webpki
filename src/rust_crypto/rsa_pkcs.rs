use rsa::traits::PublicKeyParts;
use untrusted::Input;
use crate::{alg_id, error::Error, rust_crypto::RustCryptoVerificationAlgorithm};
use signature::digest::Digest as _;

pub(super) struct RsaPkcs1 {
    pub(super) alg: pki_types::AlgorithmIdentifier,
    pub(super) n_min_bits: usize,
    pub(super) n_max_bits: usize,
}

impl RustCryptoVerificationAlgorithm for RsaPkcs1 {
    fn verify(&self, public_key: Input, msg: Input, signature: Input) -> Result<(), Error> {
        use rsa::pkcs1::DecodeRsaPublicKey as _;

        let msg = msg.as_slice_less_safe();
        let signature = signature.as_slice_less_safe();

        let pk = public_key.as_slice_less_safe();
        let public_key = rsa::RsaPublicKey::from_pkcs1_der(pk).map_err(|_| Error::UnsupportedPublicKey)?;

        // returns size in bytes ; we need bits
        let n_size = public_key.size() * 8;
        if n_size < self.n_min_bits || n_size > self.n_max_bits {
            return Err(Error::UnsupportedPublicKey);
        }

        if self.alg == alg_id::RSA_PKCS1_SHA256 {
            let digest = rsa::sha2::Sha256::digest(msg);
            let scheme = rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha256>();
            public_key.verify(scheme, &digest, signature)
        } else if self.alg == alg_id::RSA_PKCS1_SHA384 {
            let digest = rsa::sha2::Sha384::digest(msg);
            let scheme = rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha384>();
            public_key.verify(scheme, &digest, signature)
        } else if self.alg == alg_id::RSA_PKCS1_SHA512 {
            let digest = rsa::sha2::Sha512::digest(msg);
            let scheme = rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha512>();
            public_key.verify(scheme, &digest, signature)
        } else {
            return Err(Error::UnsupportedSignatureAlgorithm);
        }.map_err(|_| Error::InvalidSignatureForPublicKey)
    }
}
