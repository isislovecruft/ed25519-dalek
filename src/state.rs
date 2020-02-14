// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! [Compile-time type-dependent state machines][typestate] for aggregate signatures.
//!
//! Aggregatable signatures are compact signatures over many, potentially
//! different, messages made by several parties whose public keys are also
//! aggregatable into one single compact key.  This allows for verification of
//! one aggregated signature with one aggregated public key over a message,
//! saving space over the standard batch verification method.  The aggregate
//! signing protocol is an online, 3-round protocol.
//!
//! This construction is the MSDL protocol from ["Compact Multi-Signatures for
//! Smaller Blockchains"][msdl] by Boneh, Drijvers, and Neven.  It also allows
//! for efficient batch verification, like standard ed25519 signatures, however,
//! batch verification of aggregate signatures is has not yet been implemented
//! here.
//!
//! [typestate]: http://cliffle.com/blog/rust-typestate/
//! [msdl]: https://eprint.iacr.org/2018/483
//!
//! # Example
//!
//! ```
//! use curve25519_dalek::scalar::Scalar;
//! use curve25519_dalek::edwards::EdwardsPoint;
//!
//! use ed25519_dalek::{Keypair, PublicKey};
//! use ed25519_dalek::{AggregateSigning, RoundOne};
//! # use ed25519_dalek::{AggregateSignature, AggregateSigningState, SignatureError};
//!
//! use rand::rngs::OsRng;
//!
//! use sha2::Sha512;
//!
//! # fn do_test() -> Result<(), SignatureError> {
//! // To start, you must have your own keypair.
//! let mut csprng = OsRng{};
//! let my_keypair = Keypair::generate(&mut csprng);
//!
//! // At some point before the aggregate signing protocol, or during the
//! // communications phases of either round one or round two, you must collect
//! // an ordered list of the public keys of the other signers.
//! let mut their_public_keys: Vec<PublicKey> = Vec::new();
//!
//! // For example's sake, we generate them for Alice and Bob here:
//! let alice_keypair = Keypair::generate(&mut csprng);
//! let bob_keypair = Keypair::generate(&mut csprng);
//!
//! their_public_keys.push(alice_keypair.public);
//! their_public_keys.push(bob_keypair.public);
//!
//! // We'll also need all the public keys to create the aggregate public key
//! // later on.  Note that it's vital that this vector be in the same order for
//! // all signing parties.
//! let mut all_public_keys = their_public_keys.clone();
//! all_public_keys.push(my_keypair.public);
//!
//! // Create our protocol state machine.
//! let state_machine = AggregateSigning::<RoundOne>::new(&mut csprng);
//!
//! // Create the aggregated public keypair from our keypair and the other
//! // signers' public keys.
//! let state_machine = state_machine.create_aggregate_key(&all_public_keys, my_keypair);
//! let aggregate_public_key = state_machine.aggregate_public_key();
//!
//! // At this point, you can access a commitment to an ephemeral public value,
//! // which you should send to all other signing parties.  The commitment is
//! // accessible at this point in the protocol as:
//! let my_commitment = state_machine.my_commitment();
//!
//! // Obviously, you should then send it.
//! //
//! // send_to_other_signers(my_commitment);
//! //
//! // And await their responses containing their commitments to their ephemeral
//! // public values:
//! let mut their_commitments: Vec<Scalar> = Vec::new();
//!
//! // receive_from_other_signers(&mut their_commitments);
//! #
//! # // Setup fake protocol runs for the other signers:
//! # let alice_state = AggregateSigning::<RoundOne>::new(&mut csprng);
//! # let bob_state = AggregateSigning::<RoundOne>::new(&mut csprng);
//! #
//! # their_commitments.push(alice_state.my_commitment());
//! # their_commitments.push(bob_state.my_commitment());
//! #
//! # let mut alice_their_commitments: Vec<Scalar> = Vec::new();
//! # let mut bob_their_commitments: Vec<Scalar> = Vec::new();
//! #
//! # alice_their_commitments.push(bob_state.my_commitment());
//! # alice_their_commitments.push(state_machine.my_commitment());
//! #
//! # bob_their_commitments.push(alice_state.my_commitment());
//! # bob_their_commitments.push(state_machine.my_commitment());
//!
//! // Once you have collected all their commitments, you may proceed to round
//! // two of the protocol:
//! let state_machine = state_machine.to_round_two(their_commitments);
//!
//! // At this point, you now have access to the opening to your commitment,
//! // that is, your ephemeral public key, which you should send to all the
//! // other signers.
//! let my_ephemeral_public = state_machine.my_ephemeral_public();
//!
//! // send_to_other_signers(state_machine.my_ephemeral_public());
//! //
//! // And await their responses containing their commitment openings:
//! let mut their_ephemeral_publics: Vec<EdwardsPoint> = Vec::new();
//!
//! // receive_from_other_signers(&mut their_ephemeral_publics);
//! //
//! # // Move everyone else's execution to round two.
//! # let alice_state = alice_state.to_round_two(alice_their_commitments);
//! # let bob_state = bob_state.to_round_two(bob_their_commitments);
//! #
//! # // Compute the aggregated public keys.
//! # let mut alice_state = alice_state.create_aggregate_key(&all_public_keys, alice_keypair);
//! # let mut bob_state = bob_state.create_aggregate_key(&all_public_keys, bob_keypair);
//! #
//! # their_ephemeral_publics.push(alice_state.my_ephemeral_public());
//! # their_ephemeral_publics.push(bob_state.my_ephemeral_public());
//! #
//! # let mut alice_their_publics: Vec<EdwardsPoint> = Vec::new();
//! # let mut bob_their_publics: Vec<EdwardsPoint> = Vec::new();
//! #
//! # alice_their_publics.push(bob_state.my_ephemeral_public());
//! # alice_their_publics.push(state_machine.my_ephemeral_public());
//! #
//! # bob_their_publics.push(alice_state.my_ephemeral_public());
//! # bob_their_publics.push(state_machine.my_ephemeral_public());
//! #
//! // Now you're ready to move on to round three of the protocol.  However, be
//! // aware that the end of round two will `Result` in a `SignatureError` if
//! // any of the openings were not valid for their respective commitment.
//! let state_machine = state_machine.to_round_three(their_ephemeral_publics)?;
//!
//! # // Move everyone else's execution to round three.
//! # let alice_state = alice_state.to_round_three(alice_their_publics)?;
//! # let bob_state = bob_state.to_round_three(bob_their_publics)?;
//! #
//! // We can now compute our partial signature for a common message. Note that
//! // all signers must sign *the same message*.
//! let message = b"All Computers Are Bad";
//!
//! let state_machine = state_machine.partial_sign(&message[..]);
//!
//! let my_partial_signature = state_machine.my_partial_signature();
//!
//! // Once again, we must send our partial signature to all the other signers...
//! //
//! // send_to_other_signers(my_partial_signature);
//! //
//! // ... and wait to collect all other partial signatures from the other
//! // signers.
//! let mut their_partial_signatures: Vec<Scalar> = Vec::new();
//!
//! // receive_from_other_signers(&mut their_partial_signatures);
//! #
//! # // Compute partial signatures for everyone else.
//! # let alice_state = alice_state.partial_sign(&message[..]);
//! # let bob_state = bob_state.partial_sign(&message[..]);
//! #
//! # their_partial_signatures.push(alice_state.my_partial_signature());
//! # their_partial_signatures.push(bob_state.my_partial_signature());
//! #
//! # let mut alice_their_partials: Vec<Scalar> = Vec::new();
//! # let mut bob_their_partials: Vec<Scalar> = Vec::new();
//! #
//! # alice_their_partials.push(bob_state.my_partial_signature());
//! # alice_their_partials.push(state_machine.my_partial_signature());
//! #
//! # bob_their_partials.push(alice_state.my_partial_signature());
//! # bob_their_partials.push(state_machine.my_partial_signature());
//! //
//! // We can now move on to compute the final aggregated signature.
//! let aggregated_signature = state_machine.finish(&their_partial_signatures);
//! #
//! # // Finish the protocol for everyone else.
//! # let alice_aggregated_signature = alice_state.finish(&alice_their_partials);
//! # let bob_aggregated_signature = bob_state.finish(&bob_their_partials);
//! #
//!
//! // To verify the aggregate signature, do:
//! aggregate_public_key.verify(&aggregated_signature, &message[..])
//! #
//! # } // End do_test()
//! # fn main() {
//! #    do_test().unwrap();
//! # }
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
use crate::aggregate::AggregateSignature;
use crate::ed25519::Keypair;
use crate::errors::InternalError;
use crate::errors::SignatureError;
use crate::public::PublicKey;
use crate::secret::ExpandedSecretKey;

/// Module to implement trait sealing so that `AggregateSigningState` cannot be
/// implemented for externally declared types.
mod private {
    pub trait Sealed {}

    impl Sealed for super::RoundOne {}
    impl Sealed for super::RoundOneWithKey {}
    impl Sealed for super::RoundTwo {}
    impl Sealed for super::RoundTwoWithKey {}
    impl Sealed for super::RoundThree {}
    impl Sealed for super::PartialSignature {}
}

/// State machine structures for holding intermediate values during an aggregate
/// signing protocol run, to prevent misuse.
pub struct AggregateSigning<S: AggregateSigningState> {
    state: Box<ActualState>,
    data: S,
}

struct ActualState {
    my_ephemeral_secret: Scalar,
    my_ephemeral_public: EdwardsPoint,
    my_commitment: Scalar,
    their_commitments: Option<Vec<Scalar>>,
    their_ephemeral_publics: Option<Vec<EdwardsPoint>>,
}

/// Round one of the aggregate signing protocol.
///
/// During this round, an ephemeral secret key and ephemeral public key are
/// computed, and a commitment to the ephemeral public key is formed.  The
/// commitment should be given to all other signing parties, and this signer
/// must wait and collect all the other signers' commitments.
pub struct RoundOne {}

/// Round one of the aggregate signing protocol.
///
/// During this round, an ephemeral secret key and ephemeral public key are
/// computed, and a commitment to the ephemeral public key is formed.  The
/// commitment, available by calling `my_commitment()`, should be given to all
/// other signing parties, and this signer must wait and collect all the other
/// signers' commitments.
///
/// This is a variant of [`RoundOne`] which holds the [`AggregateKeypair`], so
/// that we can ensure at compile time that [`RoundThree`] is only ever entered
/// with the correct type state.
pub struct RoundOneWithKey {
    aggregate_keypair: AggregateKeypair,
}

/// Round two of the aggregate signing protocol.
///
/// During this round, this signer should send their opening to their
/// commitment, available by calling `my_ephemeral_public()`, to all the other
/// signers, and await their openings in response.  Finally this signer checks
/// that all the other signers' openings are valid for the commitments received
/// in round one.
pub struct RoundTwo {}

/// Round two of the aggregate signing protocol.
///
/// During this round, this signer should send their opening to their
/// commitment, available by calling `my_ephemeral_public()`, to all the other
/// signers, and await their openings in response.  Finally this signer checks
/// that all the other signers' openings are valid for the commitments received
/// in round one.
///
/// This is a variant of [`RoundTwo`] which holds the [`AggregateKeypair`], so
/// that we can ensure at compile time that [`RoundThree`] is only ever entered
/// with the correct type state.
pub struct RoundTwoWithKey {
    aggregate_keypair: AggregateKeypair,
}

/// Round three of the aggregate signing protocol.
///
/// During this round, this signer using the [`AggregateKeypair`] to compute an
/// aggregated `R` portion of the aggregate signature, as well as their own
/// "partial signature", `s` on the message.  They then send this `s` to all the
/// other signers, and await each other's `s` in response.  Finally, once all
/// the partial signatures have been received, they aggregate the final portion
/// of the signature.
pub struct RoundThree {
    aggregate_keypair: AggregateKeypair,
}

/// A partially computed signature, which has yet to be aggregated at the end of
/// round three.
#[allow(non_snake_case)]
pub struct PartialSignature {
    R_prime: EdwardsPoint,
    si: Scalar,
}

/// Marker trait to designate valid variants of [`RoundOne`] in the aggregate
/// signing protocol's state machine.  It is implemented using the [sealed trait
/// design pattern][sealed] pattern to prevent external types from implementing
/// further valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Round1: private::Sealed {}

/// Marker trait to designate valid variants of [`RoundTwo`] in the aggregate
/// signing protocol's state machine.  It is implemented using the [sealed trait
/// design pattern][sealed] pattern to prevent external types from implementing
/// further valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Round2: private::Sealed {}

impl Round1 for RoundOne {}
impl Round1 for RoundOneWithKey {}
impl Round2 for RoundTwo {}
impl Round2 for RoundTwoWithKey {}

/// Marker trait to designate valid rounds in the aggregate signing protocol's
/// state machine.  It is implemented using the [sealed trait design
/// pattern][sealed] pattern to prevent external types from implementing further
/// valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait AggregateSigningState: private::Sealed {}

impl AggregateSigningState for RoundOne {}
impl AggregateSigningState for RoundOneWithKey {}
impl AggregateSigningState for RoundTwo {}
impl AggregateSigningState for RoundTwoWithKey {}
impl AggregateSigningState for RoundThree {}
impl AggregateSigningState for PartialSignature {}

impl AggregateSigning<RoundOne> {
    /// Use a previously computed [`AggregateKeypair`] for this instance of the
    /// aggregate signing protocol.
    ///
    /// # Note
    ///
    /// Retaining an aggregate keypair can speed up future invocations of the
    /// protocol.
    ///
    /// # Returns
    ///
    /// An updated typestate machine.
    pub fn use_precomputed_aggregate_keypair(self, aggregate_keypair: AggregateKeypair)
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
    /// Use a previously computed [`AggregateKeypair`] for this instance of the
    /// aggregate signing protocol.
    ///
    /// # Note
    ///
    /// Retaining an aggregate keypair can speed up future invocations of the
    /// protocol.
    ///
    /// # Returns
    ///
    /// An updated typestate machine.
    pub fn use_precomputed_aggregate_keypair(self, aggregate_keypair: AggregateKeypair)
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
    /// Aggregate several public keys and this signer's keypair into an
    /// [`AggregateKeypair`] and store it in our state.
    ///
    /// # Warning
    ///
    /// All parties in the aggregate signing protocol **MUST** provide the
    /// `all_public_keys` vector with identical ordering, otherwise a different
    /// aggregate public key will be computed, do to the vector of public keys
    /// being passed into a protocol transcript which hashes the state.
    ///
    /// # Returns
    ///
    /// An updated typestate machine.
    pub fn create_aggregate_key(self, all_public_keys: &Vec<PublicKey>, my_keypair: Keypair)
        -> AggregateSigning<RoundOneWithKey>
    {
        let aggregate_keypair = AggregateKeypair::new(all_public_keys, my_keypair);

        self.use_precomputed_aggregate_keypair(aggregate_keypair)
    }
}

impl AggregateSigning<RoundTwo> {
    /// Aggregate several public keys and this signer's keypair into an
    /// [`AggregateKeypair`] and store it in our state.
    ///
    /// # Warning
    ///
    /// All parties in the aggregate signing protocol **MUST** provide the
    /// `all_public_keys` vector with identical ordering, otherwise a different
    /// aggregate public key will be computed, do to the vector of public keys
    /// being passed into a protocol transcript which hashes the state.
    ///
    /// # Returns
    ///
    /// An updated typestate machine.
    pub fn create_aggregate_key(self, all_public_keys: &Vec<PublicKey>, my_keypair: Keypair)
        -> AggregateSigning<RoundTwoWithKey>
    {
        let aggregate_keypair = AggregateKeypair::new(all_public_keys, my_keypair);

        self.use_precomputed_aggregate_keypair(aggregate_keypair)
    }
}

fn commit_to_ephemeral_public(public: EdwardsPoint) -> Scalar {
    let mut t: Sha512 = Sha512::new();
    let compressed: CompressedEdwardsY = public.compress(); // XXX these should already be compressed

    t.input("ed25519-dalek aggregate sign cmt");
    t.input(compressed.as_bytes());

    Scalar::from_hash(t)
}

#[allow(non_snake_case)]
impl AggregateSigning<RoundOne> {
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
    /// A typestate machine.
    pub fn new<T>(csprng: &mut T) -> Self
    where
        T: CryptoRng + RngCore,
    {
        let r: Scalar = Scalar::random(csprng);
        let R: EdwardsPoint = &ED25519_BASEPOINT_TABLE * &r;
        let t: Scalar = commit_to_ephemeral_public(R);

        let state = ActualState {
            my_ephemeral_secret: r,
            my_ephemeral_public: R,
            my_commitment: t,
            their_commitments: None,
            their_ephemeral_publics: None,
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
    /// Access this signer's commitment to their ephemeral public key.
    ///
    /// This value should be given to all other signers during round one of the
    /// aggregate signing protocol.
    pub fn my_commitment(&self) -> Scalar {
        self.state.my_commitment.clone()
    }
}

impl AggregateSigning<RoundOne> {
    /// Move to round two, once all the other signers' commitments have been
    /// received.
    pub fn to_round_two(mut self, their_commitments: Vec<Scalar>) -> AggregateSigning<RoundTwo> {
        self.state.their_commitments = Some(their_commitments);

        AggregateSigning::<RoundTwo> {
            state: self.state,
            data: RoundTwo {}
        }
    }
}

impl AggregateSigning<RoundOneWithKey> {
    /// Move to round two, once all the other signers' commitments have been
    /// received.
    pub fn to_round_two(mut self, their_commitments: Vec<Scalar>) -> AggregateSigning<RoundTwoWithKey> {
        self.state.their_commitments = Some(their_commitments);

        AggregateSigning::<RoundTwoWithKey> {
            state: self.state,
            data: RoundTwoWithKey {
                aggregate_keypair: self.data.aggregate_keypair,
            }
        }
    }

    /// Access this signer's [`AggregateKeypair`].
    pub fn aggregate_keypair(&self) -> &AggregateKeypair {
        &self.data.aggregate_keypair
    }

    /// Access this signer's [`AggregatePublicKey`].
    pub fn aggregate_public_key(&self) -> AggregatePublicKey {
        self.data.aggregate_keypair.aggregated_public
    }
}

impl<S> AggregateSigning<S>
where
    S: Round2 + AggregateSigningState,
{
    /// Access this signer's ephemeral public key, which they committed to in
    /// round one of the aggregate signing protocol.
    ///
    /// This value should be given to all other signers during round two of the
    /// aggregate signing protocol.
    pub fn my_ephemeral_public(&self) -> EdwardsPoint {
        self.state.my_ephemeral_public.clone()
    }
}

impl AggregateSigning<RoundTwoWithKey> {
    /// Access this signer's [`AggregateKeypair`].
    pub fn aggregate_keypair(&self) -> &AggregateKeypair {
        &self.data.aggregate_keypair
    }

    /// Access this signer's [`AggregatePublicKey`].
    pub fn aggregate_public_key(&self) -> AggregatePublicKey {
        self.data.aggregate_keypair.aggregated_public
    }

    /// Move to round three, once all the other signers' ephemeral public keys
    /// have been received.
    ///
    /// # Warning
    ///
    /// This is the only part of the protocol which can fail, if we are given an
    /// ephemeral public key which is not a valid opening for the commitment we
    /// previously received in round one.
    ///
    /// # Inputs
    ///
    /// * `their_ephemeral_publics` are the ephemeral public keys of all the
    ///   other signers, committed to in round one of the protocol.  THE ORDER
    ///   OF THIS VECTOR MATTERS, AS IT **MUST** MATCH THE ORDER, W.R.T. WHICH
    ///   SIGNER, OF THE COMMITMENTS RECEIVED IN ROUND ONE.  FAILURE TO PROVIDE
    ///   THESE VECTORS ORDERED ACCORDING TO SIGNER WILL RESULT IN A RUNTIME
    ///   ERROR.
    ///
    /// # Returns
    ///
    /// The updated typestate machine.
    pub fn to_round_three(mut self, their_ephemeral_publics: Vec<EdwardsPoint>)
        -> Result<AggregateSigning<RoundThree>, SignatureError>
    {
        // The unwrap() here cannot fail because the only way to get to this
        // state is by calling AggregateSigning::<RoundOne{WithKey}>::finish()
        // which takes the commitments.
        let their_commitments = self.state.their_commitments.clone().unwrap();

        // The vectors must be the same size.
        if their_commitments.len() != their_ephemeral_publics.len() {
            return Err(SignatureError(InternalError::AggregateSigningVectorLengthError));
        }

        // Check that the commitment openings are valid
        for i in 0..their_commitments.len() {
            let commitment = commit_to_ephemeral_public(their_ephemeral_publics[i]);

            // We don't care about constant-timedness since these are hashes of public values.
            if commitment != their_commitments[i] {
                return Err(SignatureError(InternalError::AggregateSigningCommitmentOpenError));
            }
        }
        // Save state
        self.state.their_ephemeral_publics = Some(their_ephemeral_publics);

        Ok(AggregateSigning::<RoundThree> {
            state: self.state,
            data: RoundThree {
                aggregate_keypair: self.data.aggregate_keypair,
            }
        })
    }
}

impl AggregateSigning<RoundThree> {
    /// Compute this signer's share of what will eventually be the aggregate
    /// signature.
    ///
    /// # Inputs
    ///
    /// * `message`, a slice of bytes to be signed.  In this protocol, all
    ///   signers must sign the same message.
    ///
    /// # Returns
    ///
    /// The updated typestate machine.
    #[allow(non_snake_case)]
    pub fn partial_sign(self, message: &[u8]) -> AggregateSigning<PartialSignature> {
        let mut R_prime: EdwardsPoint = self.state.my_ephemeral_public;

        // XXX i think this is wrong, it's a typo in the paper, we should be
        // using all_public_keys here, otherwise all parties will not compute
        // the same R'.
        for key in self.state.their_ephemeral_publics.clone().unwrap().iter() {
            R_prime += key;
        }

        let r:   Scalar = self.state.my_ephemeral_secret;
        let c:   Scalar = compute_challenge(&R_prime.compress(), &self.data.aggregate_keypair.aggregated_public, message);
        let ski: Scalar = ExpandedSecretKey::from(&self.data.aggregate_keypair.my_keypair.secret).key;
        let ai:  Scalar = self.state.my_commitment;
        let si:  Scalar = r + c * ski * ai;

        AggregateSigning::<PartialSignature> {
            // XXX hmm.. we can throw out all the state at this point; how do we best do this?
            state: self.state,
            data: PartialSignature {
                R_prime,
                si,
            }
        }
    }
}

/// XXX merge aggregate and state modules and make this non-pub
#[allow(non_snake_case)]
pub fn compute_challenge(R_prime: &CompressedEdwardsY, apk: &AggregatePublicKey, message: &[u8])
    -> Scalar
{
    let mut h: Sha512 = Sha512::new();

    h.input("ed25519-dalek aggregate sign challenge");
    h.input(R_prime.as_bytes());
    h.input(apk);
    h.input(message);

    Scalar::from_hash(h)
}

impl AggregateSigning<PartialSignature> {
    /// Access our partial signature.
    ///
    /// # Returns
    ///
    /// A [`Scalar`] representing this signer's contribution to the aggregate
    /// signature.
    pub fn my_partial_signature(&self) -> Scalar {
        self.data.si.clone()
    }

    /// Use all the other signers' `partial_signatures` to compute the final
    /// [`AggregateSignature`].
    ///
    /// # Inputs
    ///
    /// * `partial_signatures` is a `Vec<Scalar>` of all the other signers'
    ///   partial signatures computed during round three. The ordering of this
    ///   vector does not matter.
    ///
    /// # Returns
    ///
    /// An [`AggregateSignature`].
    pub fn finish(self, partial_signatures: &Vec<Scalar>) -> AggregateSignature {
        let mut s: Scalar = self.data.si.clone();

        for sj in partial_signatures.iter() {
            s *= sj; // XXX this is \sigma in the paper but R' (a point) is supposed to be a product??
        }

        AggregateSignature {
            R: self.data.R_prime.compress().clone(),
            s: s,
        }
    }
}

// XXX many more things can be &Vec<T> instead of Vec<T>

// XXX need Zeroize/Drop impls

#[cfg(test)]
mod test {
    #[cfg(feature = "std")]
    use std::vec::Vec;
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::edwards::EdwardsPoint;

    use rand::rngs::OsRng;

    use sha2::Sha512;

    use super::{Keypair, PublicKey};
    use super::{AggregateSigning, RoundOne};
    use super::{AggregateSignature, AggregateSigningState, SignatureError};

    #[test]
    fn aggregate_verify() {
        // To start, you must have your own keypair.
        let mut csprng = OsRng{};
        let my_keypair = Keypair::generate(&mut csprng);

        // At some point before the aggregate signing protocol, or during the
        // communications phases of either round one or round two, you must collect
        // an ordered list of the public keys of the other signers.
        let mut their_public_keys: Vec<PublicKey> = Vec::new();

        // For example's sake, we generate them for Alice and Bob here:
        let alice_keypair = Keypair::generate(&mut csprng);
        let bob_keypair = Keypair::generate(&mut csprng);

        their_public_keys.push(alice_keypair.public);
        their_public_keys.push(bob_keypair.public);

        // We'll also need all the public keys to create the aggregate public key
        // later on.  Note that it's vital that this vector be in the same order for
        // all signing parties.
        let mut all_public_keys = their_public_keys.clone();
        all_public_keys.push(my_keypair.public);

        // Create our protocol state machine.
        let state_machine = AggregateSigning::<RoundOne>::new(&mut csprng);

        // Create the aggregated public keypair from our keypair and the other
        // signers' public keys.
        let state_machine = state_machine.create_aggregate_key(&all_public_keys, my_keypair);
        let aggregate_public_key = state_machine.aggregate_public_key();

        // At this point, you can access a commitment to an ephemeral public value,
        // which you should send to all other signing parties.  The commitment is
        // accessible at this point in the protocol as:
        let my_commitment = state_machine.my_commitment();

        // Obviously, you should then send it.
        //
        // send_to_other_signers(my_commitment);
        //
        // And await their responses containing their commitments to their ephemeral
        // public values:
        let mut their_commitments: Vec<Scalar> = Vec::new();

        // receive_from_other_signers(&mut their_commitments);

        // Setup fake protocol runs for the other signers:
        let alice_state = AggregateSigning::<RoundOne>::new(&mut csprng);
        let bob_state = AggregateSigning::<RoundOne>::new(&mut csprng);
        
        their_commitments.push(alice_state.my_commitment());
        their_commitments.push(bob_state.my_commitment());

        let mut alice_their_commitments: Vec<Scalar> = Vec::new();
        let mut bob_their_commitments: Vec<Scalar> = Vec::new();

        alice_their_commitments.push(bob_state.my_commitment());
        alice_their_commitments.push(state_machine.my_commitment());

        bob_their_commitments.push(alice_state.my_commitment());
        bob_their_commitments.push(state_machine.my_commitment());

        // Once you have collected all their commitments, you may proceed to round
        // two of the protocol:
        let state_machine = state_machine.to_round_two(their_commitments);

        // At this point, you now have access to the opening to your commitment,
        // that is, your ephemeral public key, which you should send to all the
        // other signers.
        let my_ephemeral_public = state_machine.my_ephemeral_public();

        // send_to_other_signers(state_machine.my_ephemeral_public());
        //
        // And await their responses containing their commitment openings:
        let mut their_ephemeral_publics: Vec<EdwardsPoint> = Vec::new();

        // receive_from_other_signers(&mut their_ephemeral_publics);
        //
        // Move everyone else's execution to round two.
        let alice_state = alice_state.to_round_two(alice_their_commitments);
        let bob_state = bob_state.to_round_two(bob_their_commitments);

        // Compute the aggregated public keys.
        let mut alice_state = alice_state.create_aggregate_key(&all_public_keys, alice_keypair);
        let mut bob_state = bob_state.create_aggregate_key(&all_public_keys, bob_keypair);

        their_ephemeral_publics.push(alice_state.my_ephemeral_public());
        their_ephemeral_publics.push(bob_state.my_ephemeral_public());

        let mut alice_their_publics: Vec<EdwardsPoint> = Vec::new();
        let mut bob_their_publics: Vec<EdwardsPoint> = Vec::new();

        alice_their_publics.push(bob_state.my_ephemeral_public());
        alice_their_publics.push(state_machine.my_ephemeral_public());

        bob_their_publics.push(alice_state.my_ephemeral_public());
        bob_their_publics.push(state_machine.my_ephemeral_public());

        // Now you're ready to move on to round three of the protocol.  However, be
        // aware that the end of round two will `Result` in a `SignatureError` if
        // any of the openings were not valid for their respective commitment.
        let state_machine = state_machine.to_round_three(their_ephemeral_publics).unwrap();

        // Move everyone else's execution to round three.
        let alice_state = alice_state.to_round_three(alice_their_publics).unwrap();
        let bob_state = bob_state.to_round_three(bob_their_publics).unwrap();

        // We can now compute our partial signature for a common message. Note that
        // all signers must sign *the same message*.
        let message = b"All Computers Are Bad";

        let state_machine = state_machine.partial_sign(&message[..]);

        let my_partial_signature = state_machine.my_partial_signature();

        // Once again, we must send our partial signature to all the other signers...
        //
        // send_to_other_signers(my_partial_signature);
        //
        // ... and wait to collect all other partial signatures from the other
        // signers.
        let mut their_partial_signatures: Vec<Scalar> = Vec::new();

        // receive_from_other_signers(&mut their_partial_signatures);

        // Compute partial signatures for everyone else.
        let alice_state = alice_state.partial_sign(&message[..]);
        let bob_state = bob_state.partial_sign(&message[..]);

        their_partial_signatures.push(alice_state.my_partial_signature());
        their_partial_signatures.push(bob_state.my_partial_signature());

        let mut alice_their_partials: Vec<Scalar> = Vec::new();
        let mut bob_their_partials: Vec<Scalar> = Vec::new();

        alice_their_partials.push(bob_state.my_partial_signature());
        alice_their_partials.push(state_machine.my_partial_signature());

        bob_their_partials.push(alice_state.my_partial_signature());
        bob_their_partials.push(state_machine.my_partial_signature());
        //
        // We can now move on to compute the final aggregated signature.
        let aggregated_signature = state_machine.finish(&their_partial_signatures);

        // Finish the protocol for everyone else.
        let alice_aggregated_signature = alice_state.finish(&alice_their_partials);
        let bob_aggregated_signature = bob_state.finish(&bob_their_partials);

        // To verify the aggregate signature, do:
        let res = aggregate_public_key.verify(&aggregated_signature, &message[..]);

        assert!(res.is_ok());
    }
}
