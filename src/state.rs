// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Compile-time type-dependent state machines for aggregate signatures.
//!
//! Aggregatable signatures are compact signatures over many, potentially
//! different, messages made by several parties whose public keys are also
//! aggregatable into one single compact key.  This allows for verification of
//! one aggregated signature with one aggregated public key, over many messages,
//! saving space over the standard batch verification method.
//!
//! # Example
//!
//! ```
//!
//! ```

use std::boxed::Box;
use std::vec::Vec;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use rand::CryptoRng;
use rand::RngCore;

use sha2::Sha512;
use sha2::Digest;

use crate::aggregate::AggregateKeypair;
use crate::aggregate::AggregatePublicKey;
use crate::ed25519::Keypair;
use crate::errors::InternalError;
use crate::errors::SignatureError;
use crate::public::PublicKey;

/// Module to implement trait sealing so that `AggregateSigningState` cannot be
/// implemented for externally declared types.
mod private {
    pub trait Sealed {}

    impl Sealed for super::RoundOne {}
    impl Sealed for super::RoundOneWithKey {}
    impl Sealed for super::RoundTwo {}
    impl Sealed for super::RoundTwoWithKey {}
    impl Sealed for super::RoundThree {}
}

/// A commitment formed by taking a domain separated SHA-512 hash of the opening.
pub type Commitment = [u8; 64];

/// State machine structures for holding intermediate values during an aggregate
/// signing protocol run, to prevent misuse.
pub struct AggregateSigning<S: AggregateSigningState> {
    state: Box<ActualState>,
    pub data: S,
}

struct ActualState {
    my_ephemeral_secret: Scalar,
    my_ephemeral_public: EdwardsPoint,
    my_commitment: Commitment,
    their_commitments: Option<Vec<Commitment>>,
    their_ephemeral_publics: Option<Vec<EdwardsPoint>>,
    aggregate_ephemerals: Option<EdwardsPoint>,
}

pub struct RoundOne {}
pub struct RoundOneWithKey {
    aggregate_keypair: AggregateKeypair,
}
pub struct RoundTwo {}
pub struct RoundTwoWithKey {
    aggregate_keypair: AggregateKeypair,
}
pub struct RoundThree {
    pub my_partial_signature: Option<Scalar>,
    pub their_partial_signatures: Option<Vec<Scalar>>,
}

pub trait Round1: private::Sealed {}
pub trait Round2: private::Sealed {}

impl Round1 for RoundOne {}
impl Round1 for RoundOneWithKey {}
impl Round2 for RoundTwo {}
impl Round2 for RoundTwoWithKey {}

pub trait AggregateSigningState: private::Sealed {}

impl AggregateSigningState for RoundOne {}
impl AggregateSigningState for RoundOneWithKey {}
impl AggregateSigningState for RoundTwo {}
impl AggregateSigningState for RoundTwoWithKey {}
impl AggregateSigningState for RoundThree {}

impl AggregateSigning<RoundOne> {
    fn use_precomputed_aggregate_keypair(self, aggregate_keypair: AggregateKeypair)
        -> AggregateSigning<RoundOneWithKey>
    {
        AggregateSigning::<RoundOneWithKey> {
            state: self.state,
            data: RoundOneWithKey{
                aggregate_keypair,
            },
        }
    }
}

impl AggregateSigning<RoundTwo> {
    fn use_precomputed_aggregate_keypair(self, aggregate_keypair: AggregateKeypair)
        -> AggregateSigning<RoundTwoWithKey>
    {
        AggregateSigning::<RoundTwoWithKey> {
            state: self.state,
            data: RoundTwoWithKey{
                aggregate_keypair,
            },
        }
    }
}

impl AggregateSigning<RoundOne> {
    fn create_aggregate_key(&mut self, all_public_keys: Vec<PublicKey>, my_keypair: Keypair)
        -> AggregateSigning<RoundOneWithKey>
    {
        let apk: AggregatePublicKey = all_public_keys.into();

        // XXX make this into a more convenient/modular constructor

        let mut h = Sha512::new();
        let mut hash = [0u8; 64];

        h.input("ed25519-dalek aggregate public key");
        h.input(my_keypair.public.as_bytes());

        for pk in all_public_keys.iter() {
            h.input(pk.as_bytes());
        }
        hash.copy_from_slice(h.result().as_slice());

        let aggregate_keypair = AggregateKeypair {
            aggregated_public: apk,
            my_keypair,
            commitment: hash,
        };

        self.use_precomputed_aggregate_keypair(aggregate_keypair)
    }
}

impl AggregateSigning<RoundTwo> {
    fn create_aggregate_key(&mut self, all_public_keys: Vec<PublicKey>, my_keypair: Keypair)
        -> AggregateSigning<RoundTwoWithKey>
    {
        let apk: AggregatePublicKey = all_public_keys.into();

        // XXX make this into a more convenient/modular constructor

        let mut h = Sha512::new();
        let mut hash = [0u8; 64];

        h.input("ed25519-dalek aggregate public key");
        h.input(my_keypair.public.as_bytes());

        for pk in all_public_keys.iter() {
            h.input(pk.as_bytes());
        }
        hash.copy_from_slice(h.result().as_slice());

        let aggregate_keypair = AggregateKeypair {
            aggregated_public: apk,
            my_keypair,
            commitment: hash,
        };

        self.use_precomputed_aggregate_keypair(aggregate_keypair)
    }
}

/// Perform round one of an aggregated multiparty signing computation.
///
/// This round consists of choosing an ephemeral keypair, `(r, R)` s.t.
/// `R = G * r` and then computing a commitment to the ephemeral public key
/// as `t = H(R)`.
///
/// The resulting hash, `t`, must then be sent to all other signers in this
/// `AggregatePublicKey`.  Once you have received all `t`s from all the
/// other signers, you may send `R` and begin collecting everyone else's
/// `R`s, then move on to `sign_round_2`.
///
/// # Returns
///
/// A `AggregateSigning` state machine, and a callback function which should
/// be called once the other parties' `t`s are collected.
impl AggregateSigning<RoundOne> {
    pub fn new<T>(csprng: &mut T) -> Self
    where
        T: CryptoRng + RngCore,
    {
        let mut t: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];

        let r: Scalar = Scalar::random(&mut csprng);
        let R: EdwardsPoint = &ED25519_BASEPOINT_TABLE * &r;
        let R_compressed: CompressedEdwardsY = R.compress();

        t.input("ed25519-dalek aggregate sign rd1");
        t.input(R_compressed.as_bytes());

        hash.copy_from_slice(t.result().as_slice());

        let state = ActualState {
            my_ephemeral_secret: r,
            my_ephemeral_public: R,
            my_commitment: hash,
            their_commitments: None,
            their_ephemeral_publics: None,
            aggregate_ephemerals: None,
        };

        AggregateSigning::<RoundOne> {
            state: Box::new(state),
            data: RoundOne {}
        }
    }
}

impl<S> AggregateSigning<S>
where
    S: Round1 + AggregateSigningState,
{
    pub fn my_commitment(&self) -> &Commitment {
        &self.state.my_commitment
    }
}

impl AggregateSigning<RoundOne> {
    pub fn finish(self, their_commitments: Vec<Commitment>) -> AggregateSigning<RoundTwo> {
        self.state.their_commitments = Some(their_commitments);

        AggregateSigning::<RoundTwo> {
            state: self.state,
            data: RoundTwo {}
        }
    }
}

impl AggregateSigning<RoundOneWithKey> {
    pub fn finish(self, their_commitments: Vec<Commitment>) -> AggregateSigning<RoundTwoWithKey> {
        self.state.their_commitments = Some(their_commitments);

        AggregateSigning::<RoundTwoWithKey> {
            state: self.state,
            data: RoundTwoWithKey {
                aggregate_keypair: self.data.aggregate_keypair,
            }
        }
    }
}

impl<S> AggregateSigning<S>
where
    S: Round2 + AggregateSigningState,
{
    pub fn my_ephemeral_public(&self) -> &EdwardsPoint {
        &self.state.my_ephemeral_public
    }
}

impl AggregateSigning<RoundTwoWithKey> {
    pub fn finish(self, their_ephemeral_publics: Vec<EdwardsPoint>)
        -> Result<AggregateSigning<RoundThree>, SignatureError>
    {
        // The vectors must be the same size.  The unwrap() here cannot fail
        // because the only way to get to this state is by calling
        // AggregateSigning::<RoundOne{WithKey}>::finish() which takes the
        // commitments.
        if self.state.their_commitments.unwrap().len() != their_ephemeral_publics.len() {
            return Err(SignatureError(InternalError::AggregateSigningVectorLengthError));
        }

        let mut t: Sha512;
        let mut hash: [u8; 64] = [0u8; 64];

        // Check that the commitment openings are valid
        for i in 0..self.state.their_commitments.len() {
            t = Sha512::new();
            t.input("ed25519-dalek aggregate sign rd1");
            t.input(their_ephemeral_publics[i]);

            hash.copy_from_slice(t.result().as_bytes());

            for j in 0..64 {  // PartialEq isn't implemented for [u8; 64] :/
                if hash[j] != self.state.their_commitments.unwrap()[i][j] {
                    return Err(SignatureError(InternalError::AggregateSigningCommitmentOpenError));
                }
            }
        }
        // Save state
        self.state.their_ephemeral_publics = Some(their_ephemeral_publics);

        Ok(AggregateSigning::<RoundThree> {
            state: self.state,
            data: RoundThree {
                my_partial_signature: None,
                their_partial_signatures: None,
            }
        })
    }
}

impl AggregateSigning<RoundThree> {
    fn partial_sign() {
        unimplemented!();
    }

    fn finish() {
        unimplemented!();
    }
}
