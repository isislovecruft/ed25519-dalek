// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Traits for public key types.

use core::ops::{Neg, Mul};

use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::Sha512;

use crate::errors::InternalError;
use crate::errors::SignatureError;
use crate::signature::Signature;

/// A trait for public key types, to generalise over public keys with
/// pre-computed multiplication tables and those without.
// XXX this should also maybe require an Add impl so that we can
// implement things like aggregated or BIP32 key tables
pub trait IsPublicKey<'a>: Neg + AsRef<[u8]> + Sized {
    /// DOCDOC
    type Key: Mul<&'a Scalar> + Sized;

    /// Verify a signature on a message with this keypair's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature
    ) -> Result<(), SignatureError>
    {
        let mut h: Sha512 = Sha512::new();
        let R: EdwardsPoint;
        let k: Scalar;

        h.input(signature.R.as_bytes());
        h.input(self.as_ref());
        h.input(&message);

        k = Scalar::from_hash(h);
        R = self.vartime_double_scalar_mul_basepoint(&k, &signature.s);

        if R.compress() == signature.R {
            Ok(())
        } else {
            Err(SignatureError(InternalError::VerifyError))
        }
    }

    /// Verify a `signature` on a `prehashed_message` using the Ed25519ph algorithm.
    ///
    /// # Inputs
    ///
    /// * `prehashed_message` is an instantiated hash digest with 512-bits of
    ///   output which has had the message to be signed previously fed into its
    ///   state.
    /// * `context` is an optional context string, up to 255 bytes inclusive,
    ///   which may be used to provide additional domain separation.  If not
    ///   set, this will default to an empty string.
    /// * `signature` is a purported Ed25519ph [`Signature`] on the `prehashed_message`.
    ///
    /// # Returns
    ///
    /// Returns `true` if the `signature` was a valid signature created by this
    /// `Keypair` on the `prehashed_message`.
    ///
    /// [rfc8032]: https://tools.ietf.org/html/rfc8032#section-5.1
    #[allow(non_snake_case)]
    fn verify_prehashed<D>(
        &self,
        prehashed_message: D,
        context: Option<&[u8]>,
        signature: &Signature,
    ) -> Result<(), SignatureError>
    where
        D: Digest<OutputSize = U64>,
    {
        let mut h: Sha512 = Sha512::default();
        let R: EdwardsPoint;
        let k: Scalar;

        let ctx: &[u8] = context.unwrap_or(b"");
        debug_assert!(ctx.len() <= 255, "The context must not be longer than 255 octets.");

        h.input(b"SigEd25519 no Ed25519 collisions");
        h.input(&[1]); // Ed25519ph
        h.input(&[ctx.len() as u8]);
        h.input(ctx);
        h.input(signature.R.as_bytes());
        h.input(self.as_ref());
        h.input(prehashed_message.result().as_slice());

        k = Scalar::from_hash(h);
        R = self.vartime_double_scalar_mul_basepoint(&k, &signature.s);

        if R.compress() == signature.R {
            Ok(())
        } else {
            Err(SignatureError(InternalError::VerifyError))
        }
    }

    /// Strictly verify a signature on a message with this keypair's public key.
    ///
    /// # On The (Multiple) Sources of Malleability in Ed25519 Signatures
    ///
    /// This version of verification is technically non-RFC8032 compliant.  The
    /// following explains why.
    ///
    /// 1. Scalar Malleability
    ///
    /// The authors of the RFC explicitly stated that verification of an ed25519
    /// signature must fail if the scalar `s` is not properly reduced mod \ell:
    ///
    /// > To verify a signature on a message M using public key A, with F
    /// > being 0 for Ed25519ctx, 1 for Ed25519ph, and if Ed25519ctx or
    /// > Ed25519ph is being used, C being the context, first split the
    /// > signature into two 32-octet halves.  Decode the first half as a
    /// > point R, and the second half as an integer S, in the range
    /// > 0 <= s < L.  Decode the public key A as point A'.  If any of the
    /// > decodings fail (including S being out of range), the signature is
    /// > invalid.)
    ///
    /// All `verify_*()` functions within ed25519-dalek perform this check.
    ///
    /// 2. Point malleability
    ///
    /// The authors of the RFC added in a malleability check to step #3 in
    /// §5.1.7, for small torsion components in the `R` value of the signature,
    /// *which is not strictly required*, as they state:
    ///
    /// > Check the group equation \[8\]\[S\]B = \[8\]R + \[8\]\[k\]A'.  It's
    /// > sufficient, but not required, to instead check \[S\]B = R + \[k\]A'.
    ///
    /// # History of Malleability Checks
    ///
    /// As originally defined (cf. the "Malleability" section in the README of
    /// this repo), ed25519 signatures didn't consider *any* form of
    /// malleability to be an issue.  Later the scalar malleability was
    /// considered important.  Still later, particularly with interests in
    /// cryptocurrency design and in unique identities (e.g. for Signal users,
    /// Tor onion services, etc.), the group element malleability became a
    /// concern.
    ///
    /// However, libraries had already been created to conform to the original
    /// definition.  One well-used library in particular even implemented the
    /// group element malleability check, *but only for batch verification*!
    /// Which meant that even using the same library, a single signature could
    /// verify fine individually, but suddenly, when verifying it with a bunch
    /// of other signatures, the whole batch would fail!
    ///
    /// # "Strict" Verification
    ///
    /// This method performs *both* of the above signature malleability checks.
    ///
    /// It must be done as a separate method because one doesn't simply get to
    /// change the definition of a cryptographic primitive ten years
    /// after-the-fact with zero consideration for backwards compatibility in
    /// hardware and protocols which have it already have the older definition
    /// baked in.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    fn verify_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError>
    {
        let mut h: Sha512 = Sha512::new();
        let R: EdwardsPoint;
        let k: Scalar;
        let signature_R: EdwardsPoint;

        match signature.R.decompress() {
            None => return Err(SignatureError(InternalError::VerifyError)),
            Some(x) => signature_R = x,
        }

        // Logical OR is fine here as we're not trying to be constant time.
        if signature_R.is_small_order() || self.public_key_as_point().is_small_order() {
            return Err(SignatureError(InternalError::VerifyError));
        }

        h.input(signature.R.as_bytes());
        h.input(self.as_ref());
        h.input(&message);

        k = Scalar::from_hash(h);
        R = self.vartime_double_scalar_mul_basepoint(&k, &signature.s);

        if R == signature_R {
            Ok(())
        } else {
            Err(SignatureError(InternalError::VerifyError))
        }
    }

    /// DOCDOC
    fn vartime_double_scalar_mul_basepoint(&self, k: &Scalar, s: &Scalar) -> EdwardsPoint;
    /// DOCDOC
    fn public_key(&self) -> Self::Key;
    /// DOCDOC
    // XXX only exposed so that we can reach EdwardsPoint::is_small_order()
    fn public_key_as_point(&self) -> EdwardsPoint;
}
