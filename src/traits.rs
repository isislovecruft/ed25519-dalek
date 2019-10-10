// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Implementations of [rust-crypto
//! traits](https://github.com/RustCrypto/signatures/blob/master/signature-crate)
//! for library interoperability.
//!
//! Note that we don't implement `signature::DigestSigner` or
//! `signature::DigestVerifier` as those require a different version of the
//! `digest` dependency than we do (since we're tracking what `curve25519-dalek`
//! uses).  However, the functionality is implemented in
//! `PublicKey.verify_prehashed` and `Keypair.sign_prehashed`.

use crate::Keypair;
use crate::signature::Signature;

use signature::{Error};
use signature::Signature as SignatureTrait;
use signature::{Signer};

impl SignatureTrait for Signature {
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        Signature::from_bytes(bytes)
    }
}

pub struct Ed25519Signer(pub(crate) Keypair);

impl Signer<Signature> for Ed25519Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<S, Error> {
        
    }
}
