//! # Picnic bindings for `pqcrypto`
//!
//! This crate implements the traits from [pqcrypto_traits] for the Picnic bindings available in
//! [picnic_bindings].
//!
//! ## Usage
//!
//! ```
//! # #[cfg(feature = "picnic")] {
//! use pqcrypto_picnic::{picnic_l1_fs_keypair, picnic_l1_fs_open, picnic_l1_fs_sign};
//!
//! let (sk, pk) = picnic_l1_fs_keypair();
//! let sm = picnic_l1_fs_sign(b"a message", &sk);
//! let opened_msg = picnic_l1_fs_open(&sm, &pk).expect("signature did not verify");
//! assert_eq!(opened_msg, b"a message");
//! # }

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::mem;
use paste::paste;
pub use picnic_bindings::{self, Parameters};
use picnic_bindings::{
    signature::{Signature, Signer, Verifier},
    DynamicSignature, RawVerifier, SigningKey, VerificationKey,
};
pub use pqcrypto_traits::{
    sign::{self, VerificationError},
    Error,
};

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// A Picnic secret key
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct SecretKey<P>(SigningKey<P>)
where
    P: Parameters;

impl<P> sign::SecretKey for SecretKey<P>
where
    P: Parameters,
{
    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn from_bytes(bytes: &[u8]) -> pqcrypto_traits::Result<Self>
    where
        Self: Sized,
    {
        match SigningKey::<P>::try_from(bytes) {
            Ok(sk) => Ok(Self(sk)),
            Err(_) => Err(Error::BadLength {
                name: "SecretKey",
                actual: bytes.len(),
                expected: P::PRIVATE_KEY_SIZE,
            }),
        }
    }
}

/// A Picnic public key
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct PublicKey<P>(VerificationKey<P>)
where
    P: Parameters;

impl<P> sign::PublicKey for PublicKey<P>
where
    P: Parameters,
{
    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn from_bytes(bytes: &[u8]) -> pqcrypto_traits::Result<Self>
    where
        Self: Sized,
    {
        match VerificationKey::<P>::try_from(bytes) {
            Ok(pk) => Ok(Self(pk)),
            Err(_) => Err(Error::BadLength {
                name: "PublicKey",
                actual: bytes.len(),
                expected: P::PUBLIC_KEY_SIZE,
            }),
        }
    }
}

/// A signed message
///
/// The message and its signature are encoded in the same way as for the NIST submission of Picnic.
/// The length of the signature (u32 in little endian) is followed the message and then the signature.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct SignedMessage(
    #[cfg_attr(feature = "serialization", serde(with = "serde_bytes"))] Vec<u8>,
);

impl SignedMessage {
    /// Pack message and a signature into a signed message
    fn pack(msg: &[u8], sig: DynamicSignature) -> Self {
        let sig_data = sig.as_bytes();

        let mut data = Vec::with_capacity(mem::size_of::<u32>() + msg.len() + sig_data.len());
        data.extend_from_slice(&(sig_data.len() as u32).to_le_bytes());
        data.extend_from_slice(msg);
        data.extend_from_slice(sig_data);

        Self(data)
    }

    /// Unpack message and signature from the signed message
    fn unpack(&self) -> Result<(&[u8], &[u8]), VerificationError> {
        let sm_len = self.0.len();
        if sm_len < mem::size_of::<u32>() {
            return Err(VerificationError::InvalidSignature);
        }

        let len = u32::from_le_bytes(self.0[..4].try_into().unwrap()) as usize;
        if sm_len < len + mem::size_of::<u32>() {
            return Err(VerificationError::InvalidSignature);
        }

        let sig_offset = sm_len - len;
        let message = &self.0[mem::size_of::<u32>()..sig_offset];
        let signature = &self.0[sig_offset..];

        Ok((message, signature))
    }
}

impl sign::SignedMessage for SignedMessage {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn from_bytes(bytes: &[u8]) -> pqcrypto_traits::Result<Self>
    where
        Self: Sized,
    {
        Ok(SignedMessage(bytes.to_vec()))
    }
}

/// A detached signature
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct DetachedSignature(DynamicSignature);

impl sign::DetachedSignature for DetachedSignature {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> pqcrypto_traits::Result<Self>
    where
        Self: Sized,
    {
        Ok(DetachedSignature(DynamicSignature::from(bytes)))
    }
}

/// Generate a new Picnic key pair
pub(crate) fn keypair<P>() -> (SecretKey<P>, PublicKey<P>)
where
    P: Parameters,
{
    // the pqcrypto-* crates all provide infallible key generation; if the parameters are not
    // implemented, random will fail
    SigningKey::<P>::random()
        .map(|(sk, pk)| (SecretKey(sk), PublicKey(pk)))
        .expect("parameters not supported")
}

/// Sign a message
pub(crate) fn sign<P>(msg: &[u8], sk: &SecretKey<P>) -> SignedMessage
where
    P: Parameters,
{
    let sig = sk.0.sign(msg);
    SignedMessage::pack(msg, sig)
}

/// Verify a signed message and return the message on success
pub(crate) fn open<P>(sm: &SignedMessage, pk: &PublicKey<P>) -> Result<Vec<u8>, VerificationError>
where
    P: Parameters,
{
    let (message, signature) = sm.unpack()?;
    match pk.0.verify_raw(message, signature) {
        Ok(_) => Ok(message.to_vec()),
        Err(_) => Err(VerificationError::InvalidSignature),
    }
}

/// Generate a detached signature
pub(crate) fn detached_sign<P>(msg: &[u8], sk: &SecretKey<P>) -> DetachedSignature
where
    P: Parameters,
{
    DetachedSignature(sk.0.sign(msg))
}

/// Verify a detached signature
pub(crate) fn verify_detached_signature<P>(
    sig: &DetachedSignature,
    msg: &[u8],
    pk: &PublicKey<P>,
) -> Result<(), VerificationError>
where
    P: Parameters,
{
    pk.0.verify(msg, &sig.0)
        .map_err(|_| VerificationError::InvalidSignature)
}

/// Get the number of bytes for a public key
pub(crate) fn public_key_bytes<P>() -> usize
where
    P: Parameters,
{
    P::PUBLIC_KEY_SIZE
}

/// Get the number of bytes for a secret key
pub(crate) fn secret_key_bytes<P>() -> usize
where
    P: Parameters,
{
    P::PRIVATE_KEY_SIZE
}

/// Get the maximum number of bytes a signature occupies
pub(crate) fn signature_bytes<P>() -> usize
where
    P: Parameters,
{
    P::MAX_SIGNATURE_SIZE
}

macro_rules! define_implementation {
    ($name:ident, $parameters:ident) => {
        paste! {
            #[doc = "Implementations of [pqcrypto_traits] for Picnic parameter set " $parameters]
            pub mod $name {
                #[cfg(not(feature = "std"))]
                use alloc::vec::Vec;

                pub use crate::{DetachedSignature, Error, SignedMessage, VerificationError};
                use picnic_bindings::$parameters;

                /// A Picnic secret key
                pub type SecretKey = crate::SecretKey<$parameters>;
                /// A Picnic public key
                pub type PublicKey = crate::PublicKey<$parameters>;

                /// Generate a new Picnic key pair.
                pub fn keypair() -> (SecretKey, PublicKey) {
                    crate::keypair::<$parameters>()
                }

                /// Sign a message.
                pub fn sign(msg: &[u8], sk: &SecretKey) -> SignedMessage {
                    crate::sign(msg, sk)
                }

                /// Verify a signed message and return the message on success.
                pub fn open(sm: &SignedMessage, pk: &PublicKey) -> Result<Vec<u8>, VerificationError> {
                    crate::open(sm, pk)
                }

                /// Sign a message and generate a detached signature.
                pub fn detached_sign(msg: &[u8], sk: &SecretKey) -> DetachedSignature {
                    crate::detached_sign(msg, sk)
                }

                /// Verify a detached signature.
                pub fn verify_detached_signature(
                    sig: &DetachedSignature,
                    msg: &[u8],
                    pk: &PublicKey,
                ) -> Result<(), VerificationError> {
                    crate::verify_detached_signature(sig, msg, pk)
                }

                /// Get the number of bytes for a public key.
                pub fn public_key_bytes() -> usize {
                    crate::public_key_bytes::<$parameters>()
                }

                /// Get the number of bytes for a secret key.
                pub fn secret_key_bytes() -> usize {
                    crate::secret_key_bytes::<$parameters>()
                }

                /// Get the maximum number of bytes a signature occupies.
                pub fn signature_bytes() -> usize {
                    crate::signature_bytes::<$parameters>()
                }

                #[cfg(test)]
                mod test {
                    pub(crate) const MSG: &[u8] = b"test message";

                    #[test]
                    fn keypair() {
                        super::keypair();
                    }

                    #[test]
                    fn sign() {
                        let (sk, pk) = super::keypair();
                        let sig = super::sign(MSG, &sk);
                        assert_eq!(super::open(&sig, &pk).unwrap(), MSG);
                    }

                    #[test]
                    fn detached_sign() {
                        let (sk, pk) = super::keypair();
                        let sig = super::detached_sign(MSG, &sk);
                        assert!(super::verify_detached_signature(&sig, MSG, &pk).is_ok());
                        assert!(super::verify_detached_signature(&sig, b"other msg", &pk).is_err());
                    }

                    #[test]
                    fn sizes() {
                        assert!(super::public_key_bytes() > 0);
                        assert!(super::secret_key_bytes() > 0);
                        assert!(super::signature_bytes() > 0);
                    }
                }

                #[cfg(all(test, feature = "serialization"))]
                mod serialization_tests {
                    use super::test::MSG;
                    use serde::{Deserialize, Serialize};
                    use serde_bytes_repr::{ByteFmtSerializer, ByteFmtDeserializer};

                    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
                    struct KeyPair {
                        sk: super::SecretKey,
                        pk: super::PublicKey,
                    }

                    #[test]
                    fn serialize() {
                        let (sk, pk) = super::keypair();
                        let kp1 = KeyPair { sk, pk };

                        let mut out = vec![];
                        let mut ser = serde_json::Serializer::new(&mut out);
                        let ser = ByteFmtSerializer::hex(&mut ser);

                        kp1.serialize(ser).unwrap();
                        let serialized = String::from_utf8(out).unwrap();

                        let mut json_de = serde_json::Deserializer::from_str(&serialized);
                        let bytefmt_json_de = ByteFmtDeserializer::new_hex(&mut json_de);

                        let kp2 = KeyPair::deserialize(bytefmt_json_de).unwrap();
                        assert_eq!(kp1, kp2);
                    }

                    #[test]
                    fn serialize_signed_msg() {
                        let (sk, pk) = super::keypair();
                        let sm1 = super::sign(MSG, &sk);

                        let mut out = vec![];
                        let mut ser = serde_json::Serializer::new(&mut out);
                        let ser = ByteFmtSerializer::hex(&mut ser);

                        sm1.serialize(ser).unwrap();
                        let serialized = String::from_utf8(out).unwrap();

                        let mut json_de = serde_json::Deserializer::from_str(&serialized);
                        let bytefmt_json_de = ByteFmtDeserializer::new_hex(&mut json_de);

                        let sm2 = crate::SignedMessage::deserialize(bytefmt_json_de).unwrap();
                        assert_eq!(sm1, sm2);
                        assert_eq!(MSG, super::open(&sm2, &pk).unwrap());
                    }

                    #[test]
                    fn serialize_detached_signature() {
                        let (sk, pk) = super::keypair();
                        let sig1 = super::detached_sign(MSG, &sk);

                        let mut out = vec![];
                        let mut ser = serde_json::Serializer::new(&mut out);
                        let ser = ByteFmtSerializer::hex(&mut ser);

                        sig1.serialize(ser).unwrap();
                        let serialized = String::from_utf8(out).unwrap();

                        let mut json_de = serde_json::Deserializer::from_str(&serialized);
                        let bytefmt_json_de = ByteFmtDeserializer::new_hex(&mut json_de);

                        let sig2 = crate::DetachedSignature::deserialize(bytefmt_json_de).unwrap();
                        assert_eq!(sig1, sig2);
                        assert!(super::verify_detached_signature(&sig2, MSG, &pk).is_ok());
                    }
                }
            }

            pub use $name::{
                detached_sign as [<$name _detached_sign>],
                keypair as [<$name _keypair>],
                open as [<$name _open>],
                public_key_bytes as [<$name _public_key_bytes>],
                secret_key_bytes as [<$name _secret_key_bytes>],
                sign as [<$name _sign>],
                signature_bytes as [<$name _signature_bytes>],
                verify_detached_signature as [<$name _verify_detached_signature>],
            };
        }
    };
}

#[cfg(feature = "picnic")]

define_implementation!(picnic_l1_fs, PicnicL1FS);
#[cfg(feature = "unruh-transform")]
define_implementation!(picnic_l1_ur, PicnicL1UR);
#[cfg(feature = "picnic")]
define_implementation!(picnic_l1_full, PicnicL1Full);
#[cfg(feature = "picnic3")]
define_implementation!(picnic3_l1, Picnic3L1);

#[cfg(feature = "picnic")]
define_implementation!(picnic_l3_fs, PicnicL3FS);
#[cfg(feature = "unruh-transform")]
define_implementation!(picnic_l3_ur, PicnicL3UR);
#[cfg(feature = "picnic")]
define_implementation!(picnic_l3_full, PicnicL3Full);
#[cfg(feature = "picnic3")]
define_implementation!(picnic3_l3, Picnic3L3);

#[cfg(feature = "picnic")]
define_implementation!(picnic_l5_fs, PicnicL5FS);
#[cfg(feature = "unruh-transform")]
define_implementation!(picnic_l5_ur, PicnicL5UR);
#[cfg(feature = "picnic")]
define_implementation!(picnic_l5_full, PicnicL5Full);
#[cfg(feature = "picnic3")]
define_implementation!(picnic3_l5, Picnic3L5);
