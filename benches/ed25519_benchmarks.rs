// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2018 Isis Lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate rand;
extern crate sha2;

use criterion::Criterion;

mod ed25519_benches {
    use super::*;
    use ed25519_dalek::ExpandedSecretKey;
    use ed25519_dalek::Keypair;
    use ed25519_dalek::PublicKey;
    use ed25519_dalek::Signature;
    use ed25519_dalek::verify_batch;
    use ed25519_dalek::verify_batch_from_same_key;
    use rand::thread_rng;
    use rand::ThreadRng;
    use sha2::Sha512;

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);
        let msg: &[u8] = b"";

        c.bench_function("Ed25519 signing", move |b| {
                         b.iter(| | keypair.sign::<Sha512>(msg))
        });
    }

    fn sign_expanded_key(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);
        let expanded: ExpandedSecretKey = keypair.secret.expand::<Sha512>();
        let msg: &[u8] = b"";
        
        c.bench_function("Ed25519 signing with an expanded secret key", move |b| {
                         b.iter(| | expanded.sign::<Sha512>(msg, &keypair.public))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign::<Sha512>(msg);
        
        c.bench_function("Ed25519 signature verification", move |b| {
                         b.iter(| | keypair.verify::<Sha512>(msg, &sig))
        });
    }

    fn verify_batch_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];

        c.bench_function_over_inputs(
            "Ed25519 batch signature verification",
            |b, &&size| {
                let mut csprng: ThreadRng = thread_rng();
                let keypairs: Vec<Keypair> = (0..size).map(|_| Keypair::generate::<Sha512, _>(&mut csprng)).collect();
                let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let messages: Vec<&[u8]> = (0..size).map(|_| msg).collect();
                let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign::<Sha512>(&msg)).collect();
                let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

                b.iter(|| verify_batch::<Sha512>(&messages[..], &signatures[..], &public_keys[..]));
            },
            &BATCH_SIZES,
        );
    }

    // This bench uses the verify_batch function with the same key.
    fn verify_batch_signatures_with_same_key(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];

        c.bench_function_over_inputs(
            "Ed25519 batch signature verification with the same key",
            |b, &&size| {
                let mut csprng: ThreadRng = thread_rng();
                let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);
                let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let messages: Vec<&[u8]> = (0..size).map(|_| msg).collect();
                let signature: Signature = keypair.sign::<Sha512>(&msg);
                let signatures:  Vec<Signature> = (0..size).map(|_| signature).collect();
                let public_keys: Vec<PublicKey> = (0..size).map(|_| keypair.public).collect();

                b.iter(|| verify_batch::<Sha512>(&messages[..], &signatures[..], &public_keys[..]));
            },
            &BATCH_SIZES,
        );
    }

    // This bench uses the verify_batch_from_same_key function with the same key.
    fn verify_batch_signatures_from_same_key(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];

        c.bench_function_over_inputs(
            "Ed25519 batch signature verification with the same key cached",
            |b, &&size| {
                let mut csprng: ThreadRng = thread_rng();
                let keypair: Keypair = Keypair::generate::<Sha512, _>(&mut csprng);
                let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let messages: Vec<&[u8]> = (0..size).map(|_| msg).collect();
                let signature: Signature = keypair.sign::<Sha512>(&msg);
                let signatures:  Vec<Signature> = (0..size).map(|_| signature).collect();

                b.iter(|| verify_batch_from_same_key::<Sha512>(&messages[..], &signatures[..], &keypair.public));
            },
            &BATCH_SIZES,
        );
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();

        c.bench_function("Ed25519 keypair generation", move |b| {
                         b.iter(| | Keypair::generate::<Sha512, _>(&mut csprng))
        });
    }

    criterion_group!{
        name = ed25519_benches;
        config = Criterion::default();
        targets =
            sign,
            sign_expanded_key,
            verify,
            verify_batch_signatures,
            verify_batch_signatures_with_same_key,
            verify_batch_signatures_from_same_key,
            key_generation,
    }
}

criterion_main!(
    ed25519_benches::ed25519_benches,
);
