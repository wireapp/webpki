use pki_types::SignatureVerificationAlgorithm;
use crate::signed_data::alg_id;
use super::RustCryptoAlgorithm;

/// ED25519 signatures according to RFC 8410
pub static RUST_CRYPTO_ED25519: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    verification_alg: &super::ed25519::Ed25519,
};

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static RUST_CRYPTO_ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &super::ecdsa::EcdsaP256 { digest_alg: alg_id::ECDSA_SHA256 },
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub static RUST_CRYPTO_ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &super::ecdsa::EcdsaP256 { digest_alg: alg_id::ECDSA_SHA384 },
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub static RUST_CRYPTO_ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &super::ecdsa::EcdsaP384 { digest_alg: alg_id::ECDSA_SHA256 },
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static RUST_CRYPTO_ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &super::ecdsa::EcdsaP384 { digest_alg: alg_id::ECDSA_SHA384 },
};

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
pub static RUST_CRYPTO_RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    verification_alg: &super::rsa_pkcs::RsaPkcs1 {
        alg: alg_id::RSA_PKCS1_SHA256,
        n_min_bits: 2048,
        n_max_bits: 8192,
    },
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
pub static RUST_CRYPTO_RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    verification_alg: &super::rsa_pkcs::RsaPkcs1 {
        alg: alg_id::RSA_PKCS1_SHA384,
        n_min_bits: 2048,
        n_max_bits: 8192,
    },
};

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
pub static RUST_CRYPTO_RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    verification_alg: &super::rsa_pkcs::RsaPkcs1 {
        alg: alg_id::RSA_PKCS1_SHA512,
        n_min_bits: 2048,
        n_max_bits: 8192,
    },
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 3072-8192 bits.
pub static RUST_CRYPTO_RSA_PKCS1_3072_8192_SHA384: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    verification_alg: &super::rsa_pkcs::RsaPkcs1 {
        alg: alg_id::RSA_PKCS1_SHA384,
        n_min_bits: 3072,
        n_max_bits: 8192,
    },
};

/// RSA PSS signatures using SHA-256 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RUST_CRYPTO_RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    verification_alg: &super::rsa_pss::RsaPss {
        alg: alg_id::RSA_PSS_SHA256,
        n_min_bits: 2048,
        n_max_bits: 8192,
    },
};

/// RSA PSS signatures using SHA-384 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RUST_CRYPTO_RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    verification_alg: &super::rsa_pss::RsaPss {
        alg: alg_id::RSA_PSS_SHA384,
        n_min_bits: 2048,
        n_max_bits: 8192,
    },
};

/// RSA PSS signatures using SHA-512 for keys of 2048-8192 bits and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RUST_CRYPTO_RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &dyn SignatureVerificationAlgorithm = &RustCryptoAlgorithm {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    verification_alg: &super::rsa_pss::RsaPss {
        alg: alg_id::RSA_PSS_SHA512,
        n_min_bits: 2048,
        n_max_bits: 8192,
    },
};
