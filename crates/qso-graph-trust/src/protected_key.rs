// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Borrowed, fixed-depth RFC 5208/8018 parsing, without enabling RustCrypto ciphers or KDFs.
//! DER readers check canonical lengths and consume each sequence completely. Parsing allocates
//! nothing; iteration count and derived-key length are checked before provider work. The caller's
//! file size bound limits salt length; the .p12 reader also applies its own salt rules.

use pkcs8::ObjectIdentifier;
use pkcs8::der::{
    self, Decode, Reader, Tag,
    asn1::{AnyRef, OctetStringRef},
};
use pkcs8::spki::AlgorithmIdentifierRef;
use qso_graph_trust_awslc::{ImportCipher, ImportDigest};

const PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
const PBKDF2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");
const HMAC_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.7");
const HMAC_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");
const DES_EDE3_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.3.7");
const AES128_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
const AES256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

pub(crate) struct Envelope<'a> {
    pub algorithm: AlgorithmIdentifierRef<'a>,
    pub ciphertext: &'a [u8],
}

impl<'a> Envelope<'a> {
    pub fn from_der(bytes: &'a [u8]) -> der::Result<Self> {
        AnyRef::from_der(bytes)?.sequence(|reader| {
            Ok(Self {
                algorithm: reader.decode()?,
                ciphertext: OctetStringRef::decode(reader)?.as_bytes(),
            })
        })
    }

    pub fn parameters(&self) -> der::Result<Parameters<'a>> {
        if self.algorithm.oid != PBES2 {
            return Err(Tag::ObjectIdentifier.value_error());
        }
        Parameters::decode(required(self.algorithm)?)
    }
}

pub(crate) struct Parameters<'a> {
    pub salt: &'a [u8],
    pub iteration_count: u32,
    key_length: Option<u32>,
    pub digest: ImportDigest,
    pub cipher: ImportCipher,
    pub iv: &'a [u8],
    pub key_len: usize,
}

fn required(algorithm: AlgorithmIdentifierRef<'_>) -> der::Result<AnyRef<'_>> {
    algorithm
        .parameters
        .ok_or_else(|| Tag::Sequence.value_error())
}

impl<'a> Parameters<'a> {
    pub fn from_der(bytes: &'a [u8]) -> der::Result<Self> {
        Self::decode(AnyRef::from_der(bytes)?)
    }

    fn decode(value: AnyRef<'a>) -> der::Result<Self> {
        let (kdf, encryption) = value.sequence(|reader| {
            Ok((
                reader.decode::<AlgorithmIdentifierRef<'_>>()?,
                reader.decode::<AlgorithmIdentifierRef<'_>>()?,
            ))
        })?;
        if kdf.oid != PBKDF2 {
            return Err(Tag::ObjectIdentifier.value_error());
        }
        let (salt, iteration_count, key_length, prf) = required(kdf)?.sequence(|reader| {
            Ok((
                OctetStringRef::decode(reader)?.as_bytes(),
                reader.decode()?,
                reader.decode()?,
                reader.decode::<Option<AlgorithmIdentifierRef<'_>>>()?,
            ))
        })?;
        // RFC 8018's omitted PRF is HMAC-SHA1. Explicit PRFs have NULL parameters,
        // as in the previously used pkcs5 parser; arbitrary PRF parameters are refused.
        let digest = match prf {
            None => ImportDigest::Sha1,
            Some(prf) if required(prf)?.is_null() => match prf.oid {
                HMAC_SHA1 => ImportDigest::Sha1,
                HMAC_SHA256 => ImportDigest::Sha256,
                _ => return Err(Tag::ObjectIdentifier.value_error()),
            },
            _ => return Err(Tag::Null.value_error()),
        };
        let (cipher, key_len, iv_len) = match encryption.oid {
            DES_EDE3_CBC => (ImportCipher::DesEde3, 24, 8),
            AES128_CBC => (ImportCipher::Aes128, 16, 16),
            AES256_CBC => (ImportCipher::Aes256, 32, 16),
            _ => return Err(Tag::ObjectIdentifier.value_error()),
        };
        let iv = required(encryption)?
            .decode_as::<OctetStringRef<'_>>()?
            .as_bytes();
        if iv.len() != iv_len {
            return Err(Tag::OctetString.value_error());
        }
        Ok(Self {
            salt,
            iteration_count,
            key_length,
            digest,
            cipher,
            iv,
            key_len,
        })
    }

    pub fn accepted(&self) -> bool {
        (1..=crate::signing::MAX_PBKDF2_ITERATIONS).contains(&self.iteration_count)
            && self
                .key_length
                .is_none_or(|len| usize::try_from(len) == Ok(self.key_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{KeyError, MAX_PBKDF2_ITERATIONS, decrypt};
    use pkcs8::der::Encode;
    use pkcs8::pkcs5::{EncryptionScheme, pbes2};

    #[test]
    fn every_supported_cipher_and_prf_decrypts_independent_envelopes() {
        let salt = [7; 16];
        let iv = [9; 16];
        let plaintext = b"test-only protected plaintext";
        for encryption in [
            pbes2::EncryptionScheme::DesEde3Cbc { iv: &[9; 8] },
            pbes2::EncryptionScheme::Aes128Cbc { iv: &iv },
            pbes2::EncryptionScheme::Aes256Cbc { iv: &iv },
        ] {
            for prf in [
                pbes2::Pbkdf2Prf::HmacWithSha1,
                pbes2::Pbkdf2Prf::HmacWithSha256,
            ] {
                for key_length in [None, Some(encryption.key_size() as u16)] {
                    let oracle = pbes2::Parameters {
                        kdf: pbes2::Kdf::Pbkdf2(pbes2::Pbkdf2Params {
                            salt: &salt,
                            iteration_count: 2048,
                            key_length,
                            prf,
                        }),
                        encryption,
                    };
                    let ciphertext = oracle
                        .encrypt(b"test-password", plaintext)
                        .expect("encrypt");
                    let encoded = pkcs8::EncryptedPrivateKeyInfo {
                        encryption_algorithm: EncryptionScheme::Pbes2(oracle),
                        encrypted_data: &ciphertext,
                    }
                    .to_der()
                    .expect("envelope");
                    let envelope = Envelope::from_der(&encoded).expect("envelope");
                    let params = envelope.parameters().expect("parameters");
                    assert!(params.accepted());
                    assert_eq!(
                        &*decrypt(&params, b"test-password", envelope.ciphertext).expect("decrypt"),
                        plaintext
                    );
                }
            }
        }
    }

    fn sequence(fields: &[&[u8]]) -> Vec<u8> {
        AnyRef::new(Tag::Sequence, &fields.concat())
            .expect("sequence")
            .to_der()
            .expect("DER")
    }

    fn algorithm(oid: ObjectIdentifier, parameters: &[u8]) -> Vec<u8> {
        AlgorithmIdentifierRef {
            oid,
            parameters: Some(AnyRef::from_der(parameters).expect("parameters")),
        }
        .to_der()
        .expect("algorithm")
    }

    // Hand-encoded parameters let tests plant fields the independent pkcs5 encoder will not write.
    fn parameters(
        salt: &[u8],
        iterations: &[u8],
        tail: &[u8],
        cipher: ObjectIdentifier,
        iv: &[u8],
    ) -> Vec<u8> {
        let kdf = algorithm(
            PBKDF2,
            &sequence(&[
                &OctetStringRef::new(salt)
                    .expect("salt")
                    .to_der()
                    .expect("DER"),
                iterations,
                tail,
            ]),
        );
        let cipher = algorithm(
            cipher,
            &OctetStringRef::new(iv).expect("IV").to_der().expect("DER"),
        );
        sequence(&[&kdf, &cipher])
    }

    #[test]
    fn iteration_and_key_length_limits_are_checked_before_deriving() {
        let iv = [0; 16];
        let limit = MAX_PBKDF2_ITERATIONS.to_der().expect("iterations");
        for (salt, iterations, tail, accepted) in [
            (&[0; 64][..], limit.clone(), vec![], true),
            (&[0; 65][..], limit.clone(), vec![], true),
            (&[][..], limit.clone(), vec![], true),
            (b"salt", 0u32.to_der().expect("iterations"), vec![], false),
            (
                b"salt",
                (MAX_PBKDF2_ITERATIONS + 1).to_der().expect("iterations"),
                vec![],
                false,
            ),
            (
                b"salt",
                u32::MAX.to_der().expect("iterations"),
                vec![],
                false,
            ),
            (
                b"salt",
                limit.clone(),
                32u32.to_der().expect("length"),
                true,
            ),
            (
                b"salt",
                limit.clone(),
                16u32.to_der().expect("length"),
                false,
            ),
            (b"salt", limit, 0u32.to_der().expect("length"), false),
        ] {
            let bytes = parameters(salt, &iterations, &tail, AES256_CBC, &iv);
            let params = Parameters::from_der(&bytes).expect("parameters");
            assert_eq!(params.accepted(), accepted);
            if !accepted {
                assert_eq!(
                    decrypt(&params, b"unused", &[]).err(),
                    Some(KeyError::UnsupportedProtection)
                );
            }
        }
    }

    #[test]
    fn unsupported_algorithms_and_malformed_parameters_are_refused() {
        let count = 2048u32.to_der().expect("iterations");
        let sha1 = algorithm(HMAC_SHA1, &[5, 0]);
        let valid = parameters(b"salt", &count, &sha1, AES256_CBC, &[0; 16]);
        assert!(Parameters::from_der(&valid).expect("parameters").accepted());
        let sha512 = ObjectIdentifier::new_unwrap("1.2.840.113549.2.11");
        let aes192 = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.22");
        let missing_null = AlgorithmIdentifierRef {
            oid: HMAC_SHA256,
            parameters: None,
        }
        .to_der()
        .expect("PRF");
        for tail in [
            algorithm(sha512, &[5, 0]),
            algorithm(HMAC_SHA256, &[4, 0]),
            missing_null,
            [sha1.clone(), sha1].concat(),
            vec![2, 1, 32, 2, 1, 32],
        ] {
            assert!(
                Parameters::from_der(&parameters(b"salt", &count, &tail, AES256_CBC, &[0; 16]))
                    .is_err()
            );
        }
        for cipher in [aes192, PBKDF2] {
            assert!(
                Parameters::from_der(&parameters(b"salt", &count, &[], cipher, &[0; 16])).is_err()
            );
        }
        for (cipher, good_len) in [(AES128_CBC, 16), (AES256_CBC, 16), (DES_EDE3_CBC, 8)] {
            assert!(
                Parameters::from_der(&parameters(
                    b"salt",
                    &count,
                    &[],
                    cipher,
                    &vec![0; good_len]
                ))
                .is_ok()
            );
            for len in [0, good_len - 1, good_len + 1] {
                assert!(
                    Parameters::from_der(&parameters(b"salt", &count, &[], cipher, &vec![0; len]))
                        .is_err()
                );
            }
        }
        // Negative, oversized and nonminimal INTEGERs, trailing data and indefinite lengths.
        for iterations in [&[2, 1, 128][..], &[2, 5, 1, 0, 0, 0, 0], &[2, 2, 0, 1]] {
            assert!(
                Parameters::from_der(&parameters(b"salt", iterations, &[], AES256_CBC, &[0; 16]))
                    .is_err()
            );
        }
        for bytes in [
            &[valid.clone(), vec![5, 0]].concat()[..],
            &[48, 128, 0, 0],
            &valid[..valid.len() - 1],
        ] {
            assert!(Parameters::from_der(bytes).is_err());
        }
        // A salt source algorithm, missing parameters and an unknown KDF are unsupported.
        let cipher = algorithm(
            AES256_CBC,
            &OctetStringRef::new(&[0; 16])
                .expect("IV")
                .to_der()
                .expect("DER"),
        );
        for kdf in [
            algorithm(PBKDF2, &sequence(&[&algorithm(PBKDF2, &[5, 0]), &count])),
            AlgorithmIdentifierRef {
                oid: PBKDF2,
                parameters: None,
            }
            .to_der()
            .expect("KDF"),
            algorithm(PBES2, &sequence(&[])),
        ] {
            assert!(Parameters::from_der(&sequence(&[&kdf, &cipher])).is_err());
        }
    }

    #[test]
    fn envelopes_require_exactly_an_algorithm_and_ciphertext() {
        let params = parameters(b"salt", &[2, 1, 1], &[], AES256_CBC, &[0; 16]);
        let alg = algorithm(PBES2, &params);
        let encrypted = [4, 1, 7];
        let valid = sequence(&[&alg, &encrypted]);
        assert!(
            Envelope::from_der(&valid)
                .expect("envelope")
                .parameters()
                .is_ok()
        );
        for invalid in [
            sequence(&[&alg]),
            sequence(&[&alg, &[5, 0]]),
            sequence(&[&alg, &encrypted, &[5, 0]]),
            [valid.clone(), vec![0]].concat(),
            valid[..valid.len() - 1].to_vec(),
        ] {
            assert!(Envelope::from_der(&invalid).is_err());
        }
        let unsupported = sequence(&[&algorithm(PBKDF2, &params), &encrypted]);
        assert!(
            Envelope::from_der(&unsupported)
                .expect("envelope")
                .parameters()
                .is_err()
        );
    }
}
