// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Aggregatable ed25519 signatures.

use std::fmt::Debug;

use std::vec::Vec;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use sha2::Sha512;
use sha2::Digest;

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::constants::*;
use crate::errors::InternalError;
use crate::errors::SignatureError;
use crate::ed25519::Keypair;
use crate::public::PublicKey;
use crate::signature::check_scalar;
use crate::state::compute_challenge;

/// An aggregate ed25519 signature over many messages, made by several signers.
#[allow(non_snake_case)]
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct AggregateSignature {
    pub(crate) R: CompressedEdwardsY,
    pub(crate) s: Scalar,
}

impl Debug for AggregateSignature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "AggregateSignature( R: {:?}, s: {:?} )", &self.R, &self.s)
    }
}

impl AggregateSignature {
    /// Convert this `AggregateSignature` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];

        signature_bytes[..32].copy_from_slice(&self.R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&self.s.as_bytes()[..]);
        signature_bytes
    }

    /// Construct an `AggregateSignature` from a slice of bytes.
    ///
    /// # Scalar Malleability Checking
    ///
    /// As originally specified in the ed25519 paper (cf. the "Malleability"
    /// section of the README in this repo), no checks whatsoever were performed
    /// for signature malleability.
    ///
    /// Later, a semi-functional, hacky check was added to most libraries to
    /// "ensure" that the scalar portion, `s`, of the signature was reduced `mod
    /// \ell`, the order of the basepoint:
    ///
    /// ```ignore
    /// if signature.s[31] & 224 != 0 {
    ///     return Err();
    /// }
    /// ```
    ///
    /// This bit-twiddling ensures that the most significant three bits of the
    /// scalar are not set:
    ///
    /// ```python,ignore
    /// >>> 0b00010000 & 224
    /// 0
    /// >>> 0b00100000 & 224
    /// 32
    /// >>> 0b01000000 & 224
    /// 64
    /// >>> 0b10000000 & 224
    /// 128
    /// ```
    ///
    /// However, this check is hacky and insufficient to check that the scalar is
    /// fully reduced `mod \ell = 2^252 + 27742317777372353535851937790883648493` as
    /// it leaves us with a guanteed bound of 253 bits.  This means that there are
    /// `2^253 - 2^252 + 2774231777737235353585193779088364849311` remaining scalars
    /// which could cause malleabilllity.
    ///
    /// RFC8032 [states](https://tools.ietf.org/html/rfc8032#section-5.1.7):
    ///
    /// > To verify a signature on a message M using public key A, [...]
    /// > first split the signature into two 32-octet halves.  Decode the first
    /// > half as a point R, and the second half as an integer S, in the range
    /// > 0 <= s < L.  Decode the public key A as point A'.  If any of the
    /// > decodings fail (including S being out of range), the signature is
    /// > invalid.
    ///
    /// However, by the time this was standardised, most libraries in use were
    /// only checking the most significant three bits.  (See also the
    /// documentation for `PublicKey.verify_strict`.)
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<AggregateSignature, SignatureError> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(SignatureError(InternalError::BytesLengthError {
                name: "Signature",
                length: SIGNATURE_LENGTH,
            }));
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);

        let s: Scalar;

        match check_scalar(upper) {
            Ok(x)  => s = x,
            Err(x) => return Err(x),
        }

        Ok(AggregateSignature {
            R: CompressedEdwardsY(lower),
            s: s,
        })
    }
}

#[cfg(feature = "serde")]
impl Serialize for AggregateSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for AggregateSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct SignatureVisitor;

        impl<'d> Visitor<'d> for SignatureVisitor {
            type Value = AggregateSignature;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An aggregate ed25519 signature as 64 bytes.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Signature, E>
            where
                E: SerdeError,
            {
                Signature::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

/// An aggregated public key.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct AggregatePublicKey(pub(crate) CompressedEdwardsY, pub(crate) EdwardsPoint);

impl Debug for AggregatePublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "AggregatePublicKey({:?}), {:?})", self.0, self.1)
    }
}

impl AsRef<[u8]> for AggregatePublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> From<&'a [PublicKey]> for AggregatePublicKey {
    /// Derive an `AggregatePublicKey` from a slice of `PublicKey`s.
    ///
    /// # Example
    ///
    /// ```
    /// use ed25519_dalek::{AggregatePublicKey, Keypair, PublicKey};
    /// use rand::rngs::OsRng;
    ///
    /// let mut csprng = OsRng{};
    /// let keypairs: Vec<Keypair> = (0..32).into_iter()
    ///                                     .map(|_| Keypair::generate(&mut csprng))
    ///                                     .collect();
    ///
    /// let public_keys: Vec<PublicKey> = keypairs.iter()
    ///                                           .map(|k| k.public)
    ///                                           .collect();
    ///
    /// let aggregated: AggregatePublicKey = (&public_keys[..]).into();
    /// ```
    fn from(public_keys: &[PublicKey]) -> AggregatePublicKey {
        let mut apk: EdwardsPoint = EdwardsPoint::identity();

        for i in 0..public_keys.len() {
            let transcript: Scalar = compute_transcript(&public_keys[i], public_keys);

            apk += public_keys[i].1 * transcript; // XXX use vartime_multiscalar_mul instead
        }

        AggregatePublicKey(apk.compress(), apk)
    }
}

fn compute_transcript(my_public_key: &PublicKey, all_public_keys: &[PublicKey]) -> Scalar {
    let mut h = Sha512::new();
    let mut hash = [0u8; 64];

    h.input("ed25519-dalek aggregate public key");
    h.input(my_public_key.as_bytes());

    // XXX should we modify this to have this be the prefix so we can
    // clone the hash's state and avoid rehashing every time?
    for pk in all_public_keys.iter() {
        h.input(pk.as_bytes());
    }
    hash.copy_from_slice(h.result().as_slice());

    Scalar::from_bytes_mod_order_wide(&hash)
}

impl From<&Vec<PublicKey>> for AggregatePublicKey {
    fn from(public_keys: &Vec<PublicKey>) -> AggregatePublicKey {
        (&public_keys[..]).into()
    }
}

impl AggregatePublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        &(self.0).0
    }

    /// Construct an `AggregatePublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// The caller is responsible for ensuring that the bytes passed into this
    /// method actually represent a `curve25519_dalek::curve::CompressedEdwardsY`
    /// and that said compressed point is actually a point on the curve,
    /// otherwise an error will be raised.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate ed25519_dalek;
    /// #
    /// use ed25519_dalek::AggregatePublicKey;
    /// use ed25519_dalek::PUBLIC_KEY_LENGTH;
    /// use ed25519_dalek::SignatureError;
    ///
    /// # fn doctest() -> Result<AggregatePublicKey, SignatureError> {
    /// let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [
    ///    215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
    ///     14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
    ///
    /// let apk = AggregatePublicKey::from_bytes(&public_key_bytes)?;
    /// #
    /// # Ok(apk)
    /// # }
    /// #
    /// # fn main() {
    /// #     doctest().unwrap();
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an `AggregatePublicKey` or whose error value
    /// is an `SignatureError` describing the error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<AggregatePublicKey, SignatureError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignatureError(InternalError::BytesLengthError {
                name: "AggregatePublicKey",
                length: PUBLIC_KEY_LENGTH,
            }));
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let compressed = CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or(SignatureError(InternalError::PointDecompressionError))?;

        Ok(AggregatePublicKey(compressed, point))
    }

    /// Verify an [`AggregateSignature`] on a `message` with this aggregate public key.
    #[allow(non_snake_case)]
    pub fn verify(&self, signature: &AggregateSignature, message: &[u8]) -> Result<(), SignatureError> {
        let c = compute_challenge(&signature.R, &self, message);
        let R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-c), &self.1, &signature.s);

        if R.compress() == signature.R {
            return Ok(());
        }
        Err(SignatureError(InternalError::VerifyError))
    }
}

/// An aggregated public key, along with our [`Keypair`] and a commitment to our
/// public key.
#[derive(Debug, Default)]
pub struct AggregateKeypair {
    /// An aggregation of several [`PublicKey`]s.
    pub aggregated_public: AggregatePublicKey,
    /// This signer's [`Keypair`].
    pub my_keypair: Keypair,
    /// A commitment to this signer's [`PublicKey`] formed by taking the SHA-512
    /// digest of the [`PublicKey`] and converting it into a [`Scalar`] by reducing
    /// modulo the group order.
    pub(crate) commitment: Scalar,
}

impl AggregateKeypair {
    /// Create an [`AggregateKeypair`].
    ///
    /// # Warning
    ///
    /// All parties in the aggregate signing protocol **MUST** provide the
    /// `all_public_keys` vector with identical ordering, otherwise a different
    /// aggregate public key will be computed, do to the vector of public keys
    /// being passed into a protocol transcript which hashes the state.
    pub fn new(all_public_keys: &Vec<PublicKey>, my_keypair: Keypair) -> AggregateKeypair {
        let apk: AggregatePublicKey = (all_public_keys[..]).into();
        let transcript: Scalar = compute_transcript(&my_keypair.public, &all_public_keys[..]);

        AggregateKeypair {
            aggregated_public: apk,
            my_keypair,
            commitment: transcript,
        }
    }
}
