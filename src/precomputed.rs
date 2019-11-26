// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! ed25519 public keys with precomputed multiplication tables.
//!
//! This allows us to dramatically speed up multiple signature verifications
//! with the same public key.

use core::fmt::Debug;
use core::ops::{Neg, Mul};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsBasepointTable;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::errors::SignatureError;
use crate::public::PublicKey;
use crate::secret::ExpandedSecretKey;
use crate::secret::SecretKey;
use crate::signature::Signature;
use crate::traits::IsPublicKey;

/// An ed25519 public key which has precomputed scalar multiplication
/// tables, to greatly speed up signature verification.
#[derive(Clone)]
pub struct PublicKeyTable(pub(crate) CompressedEdwardsY, pub(crate) EdwardsBasepointTable);

impl AsRef<[u8]> for PublicKeyTable {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Debug for PublicKeyTable {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKeyTable({:?}), {:?})", self.0, self.1)
    }
}

// XXX the public key needs to be negated *before* the table mulltiplication is
// applied, so i think the table needs to be generated from the pre-negated
// point.
impl<'a> Neg for &'a PublicKeyTable {
    type Output = EdwardsPoint;

    fn neg(self) -> EdwardsPoint {
        -(&self.1.basepoint())
    }
}

impl <'a, 'b> Mul<&'b Scalar> for &'a PublicKeyTable {
    type Output = EdwardsPoint;

    fn mul(self, scalar: &'b Scalar) -> EdwardsPoint {
        self.1.mul(scalar)
    }
}

impl <'a, 'b> Mul<&'a PublicKeyTable> for &'b Scalar {
    type Output = EdwardsPoint;

    fn mul(self, table: &'a PublicKeyTable) -> EdwardsPoint {
        table * self
    }
}

impl<'a> From<&'a SecretKey> for PublicKeyTable {
    /// Derive this public key with precomputed scalar multiplication
    /// tables from its corresponding [`SecretKey`].
    fn from(secret_key: &SecretKey) -> PublicKeyTable {
        let public_key: PublicKey = secret_key.into();

        PublicKeyTable::from(&public_key)
    }
}

impl<'a> From<&'a ExpandedSecretKey> for PublicKeyTable {
    /// Derive this public key with precomputed scalar multiplication
    /// tables from its corresponding [`ExpandedSecretKey`].
    fn from(expanded_secret_key: &ExpandedSecretKey) -> PublicKeyTable {
        let public_key: PublicKey = expanded_secret_key.into();

        PublicKeyTable::from(&public_key)
    }
}

impl<'a> From<&'a PublicKey> for PublicKeyTable {
    /// Derive this public key with precomputed scalar multiplication
    /// tables from its corresponding [`PublicKey`].
    fn from(public_key: &PublicKey) -> PublicKeyTable {
        let table: EdwardsBasepointTable = EdwardsBasepointTable::create(&public_key.1);

        PublicKeyTable (public_key.0.clone(), table)
    }
}

impl PublicKeyTable {
    // XXX do we want to_bytes and from_bytes implementations? should they
    // serialise the whole table? or just the public key?

    // XXX serde support also??

    /// DOCDOC
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature
    ) -> Result<(), SignatureError>
    {
        <&Self as IsPublicKey>::verify(&self, message, signature)
    }

    /// DOCDOC
    pub fn verify_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &Signature,
    ) -> Result<(), SignatureError>
    where
        D: Digest<OutputSize = U64>,
    {
        <&Self as IsPublicKey>::verify_prehashed(&self, prehashed_message, context, signature)
    }

    /// DOCDOC
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError>
    {
        <&Self as IsPublicKey>::verify_strict(&self, message, signature)
    }
}

impl<'a> IsPublicKey<'_> for &'a PublicKeyTable {
    type Key = &'a EdwardsBasepointTable;

    fn vartime_double_scalar_mul_basepoint(&self, k: &Scalar, s: &Scalar) -> EdwardsPoint {
        s * &ED25519_BASEPOINT_TABLE - k * &self.1
    }

    fn public_key(&self) -> Self::Key {
        &&self.1
    }

    fn public_key_as_point(&self) -> EdwardsPoint {
        self.1.basepoint()
    }
}

//impl Vartime // XXX no, look at VartimeMultiscalarMul versus VartimePrecomputedMultiscalarMul
//
// impl<T> VartimePrecomputedMultiscalarMul for T
// where
//     T: IsPublicKey,
// {
//     type Point: T;
// 
//     fn optional_mixed_multiscalar_mul<I, J, K>(
//         &self,
//         static_scalars: I,
//         dynamic_scalars: J,
//         dynamic_points: K,
//     ) -> Option<Self::Point>
//     where
//         I: IntoIterator,
//         I::Item: Borrow<Scalar>,
//         J: IntoIterator,
//         J::Item: Borrow<Scalar>,
//         K: IntoIterator<Item = Option<Self::Point>> 
//     {
// 
//     }
// }

#[cfg(test)]
mod test {
    use super::*;

    use crate::traits::IsPublicKey;
    use crate::Keypair;


    use rand::rngs::OsRng;

    #[test]
    fn table_from_public_key() {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let precomputed_key: PublicKeyTable = (&keypair.public).into();
    }

    #[test]
    fn table_verify() {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let precomputed_key: PublicKeyTable = (&keypair.public).into();
        let msg = b"";
        let signature: Signature = keypair.sign(&msg[..]);
        let result = precomputed_key.verify(&msg[..], &signature);

        assert!(result.is_ok());
    }
}
