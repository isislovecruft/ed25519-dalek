// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Integration tests for ed25519-dalek.

#[cfg(all(test, feature = "serde"))]
extern crate bincode;
extern crate ed25519_dalek;
extern crate hex;
extern crate sha2;
extern crate rand;

use ed25519_dalek::*;

use hex::FromHex;

use sha2::Sha512;

#[cfg(test)]
mod vectors {
    use std::io::BufReader;
    use std::io::BufRead;
    use std::fs::File;

    use super::*;

    // TESTVECTORS is taken from sign.input.gz in agl's ed25519 Golang
    // package. It is a selection of test cases from
    // http://ed25519.cr.yp.to/python/sign.input
    #[test]
    fn against_reference_implementation() { // TestGolden
        let mut line: String;
        let mut lineno: usize = 0;

        let f = File::open("TESTVECTORS");
        if f.is_err() {
            println!("This test is only available when the code has been cloned \
                      from the git repository, since the TESTVECTORS file is large \
                      and is therefore not included within the distributed crate.");
            panic!();
        }
        let file = BufReader::new(f.unwrap());

        for l in file.lines() {
            lineno += 1;
            line = l.unwrap();

            let parts: Vec<&str> = line.split(':').collect();
            assert_eq!(parts.len(), 5, "wrong number of fields in line {}", lineno);

            let sec_bytes: Vec<u8> = FromHex::from_hex(&parts[0]).unwrap();
            let pub_bytes: Vec<u8> = FromHex::from_hex(&parts[1]).unwrap();
            let msg_bytes: Vec<u8> = FromHex::from_hex(&parts[2]).unwrap();
            let sig_bytes: Vec<u8> = FromHex::from_hex(&parts[3]).unwrap();

            let secret: SecretKey = SecretKey::from_bytes(&sec_bytes[..SECRET_KEY_LENGTH]).unwrap();
            let public: PublicKey = PublicKey::from_bytes(&pub_bytes[..PUBLIC_KEY_LENGTH]).unwrap();
            let keypair: Keypair  = Keypair{ secret: secret, public: public };

		    // The signatures in the test vectors also include the message
		    // at the end, but we just want R and S.
            let sig1: Signature = Signature::from_bytes(&sig_bytes[..64]).unwrap();
            let sig2: Signature = keypair.sign(&msg_bytes);

            assert!(sig1 == sig2, "Signature bytes not equal on line {}", lineno);
            assert!(keypair.verify(&msg_bytes, &sig2).is_ok(),
                    "Signature verification failed on line {}", lineno);
        }
    }

    // From https://tools.ietf.org/html/rfc8032#section-7.3
    #[test]
    fn ed25519ph_rf8032_test_vector() {
        let secret_key: &[u8] = b"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
        let public_key: &[u8] = b"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
        let message: &[u8] = b"616263";
        let signature: &[u8] = b"98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";

        let sec_bytes: Vec<u8> = FromHex::from_hex(secret_key).unwrap();
        let pub_bytes: Vec<u8> = FromHex::from_hex(public_key).unwrap();
        let msg_bytes: Vec<u8> = FromHex::from_hex(message).unwrap();
        let sig_bytes: Vec<u8> = FromHex::from_hex(signature).unwrap();

        let secret: SecretKey = SecretKey::from_bytes(&sec_bytes[..SECRET_KEY_LENGTH]).unwrap();
        let public: PublicKey = PublicKey::from_bytes(&pub_bytes[..PUBLIC_KEY_LENGTH]).unwrap();
        let keypair: Keypair  = Keypair{ secret: secret, public: public };
        let sig1: Signature = Signature::from_bytes(&sig_bytes[..]).unwrap();

        let mut prehash_for_signing: Sha512 = Sha512::default();
        let mut prehash_for_verifying: Sha512 = Sha512::default();

        prehash_for_signing.input(&msg_bytes[..]);
        prehash_for_verifying.input(&msg_bytes[..]);

        let sig2: Signature = keypair.sign_prehashed(prehash_for_signing, None);

        assert!(sig1 == sig2,
                "Original signature from test vectors doesn't equal signature produced:\
                \noriginal:\n{:?}\nproduced:\n{:?}", sig1, sig2);
        assert!(keypair.verify_prehashed(prehash_for_verifying, None, &sig2).is_ok(),
                "Could not verify ed25519ph signature!");
    }
}

#[cfg(test)]
mod integrations {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify() {  // TestSignVerify
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let good: &[u8] = "test message".as_bytes();
        let bad:  &[u8] = "wrong message".as_bytes();

        let mut csprng = OsRng{};

        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign(&good);
        bad_sig  = keypair.sign(&bad);

        assert!(keypair.verify(&good, &good_sig).is_ok(),
                "Verification of a valid signature failed!");
        assert!(keypair.verify(&good, &bad_sig).is_err(),
                "Verification of a signature on a different message passed!");
        assert!(keypair.verify(&bad,  &good_sig).is_err(),
                "Verification of a signature on a different message passed!");
    }

    #[test]
    fn ed25519ph_sign_verify() {
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let good: &[u8] = b"test message";
        let bad:  &[u8] = b"wrong message";

        let mut csprng = OsRng{};

        // ugh… there's no `impl Copy for Sha512`… i hope we can all agree these are the same hashes
        let mut prehashed_good1: Sha512 = Sha512::default();
        prehashed_good1.input(good);
        let mut prehashed_good2: Sha512 = Sha512::default();
        prehashed_good2.input(good);
        let mut prehashed_good3: Sha512 = Sha512::default();
        prehashed_good3.input(good);

        let mut prehashed_bad1: Sha512 = Sha512::default();
        prehashed_bad1.input(bad);
        let mut prehashed_bad2: Sha512 = Sha512::default();
        prehashed_bad2.input(bad);

        let context: &[u8] = b"testing testing 1 2 3";

        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign_prehashed(prehashed_good1, Some(context));
        bad_sig  = keypair.sign_prehashed(prehashed_bad1,  Some(context));

        assert!(keypair.verify_prehashed(prehashed_good2, Some(context), &good_sig).is_ok(),
                "Verification of a valid signature failed!");
        assert!(keypair.verify_prehashed(prehashed_good3, Some(context), &bad_sig).is_err(),
                "Verification of a signature on a different message passed!");
        assert!(keypair.verify_prehashed(prehashed_bad2,  Some(context), &good_sig).is_err(),
                "Verification of a signature on a different message passed!");
    }

    #[cfg(feature = "batch")]
    #[test]
    fn verify_batch_seven_signatures() {
        let messages: [&[u8]; 7] = [
            b"Watch closely everyone, I'm going to show you how to kill a god.",
            b"I'm not a cryptographer I just encrypt a lot.",
            b"Still not a cryptographer.",
            b"This is a test of the tsunami alert system. This is only a test.",
            b"Fuck dumbin' it down, spit ice, skip jewellery: Molotov cocktails on me like accessories.",
            b"Hey, I never cared about your bucks, so if I run up with a mask on, probably got a gas can too.",
            b"And I'm not here to fill 'er up. Nope, we came to riot, here to incite, we don't want any of your stuff.", ];
        let mut csprng = OsRng{};
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            signatures.push(keypair.sign(&messages[i]));
            keypairs.push(keypair);
        }
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

        let result = verify_batch(&messages, &signatures[..], &public_keys[..]);

        assert!(result.is_ok());
    }

    #[test]
    fn pubkey_from_secret_and_expanded_secret() {
        let mut csprng = OsRng{};
        let secret: SecretKey = SecretKey::generate(&mut csprng);
        let expanded_secret: ExpandedSecretKey = (&secret).into();
        let public_from_secret: PublicKey = (&secret).into(); // XXX eww
        let public_from_expanded_secret: PublicKey = (&expanded_secret).into(); // XXX eww

        assert!(public_from_secret == public_from_expanded_secret);
    }

    #[cfg(feature = "batch")]
    #[test]
    fn verify_batch_malleability_torsion_component() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use rand::rngs::OsRng;

        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let msg = b"testing 1 2 3";

        // Any of E[8], except for the identity element, if added to the public
        // key and the R portion of the signature, will produce another "valid"
        // signature.
        let torsion_component = EIGHT_TORSION[1];

        // Make the same public key with added torsion component.
        let pk_altered = keypair.public.to_bytes();
        let pk_altered_point = CompressedEdwardsY(pk_altered).decompress().unwrap() + torsion_component;
        let pk_malicious = PublicKey::from_bytes(&pk_altered_point.compress().to_bytes()).unwrap();

        // Make a completely unrelated, honest signer.
        let third_party_keypair = Keypair::generate(&mut csprng);
        let third_party_sig = third_party_keypair.sign(&msg[..]);

        // Sign the message with the untampered-with keypair.
        let ok_sig = keypair.sign(&msg[..]);

        // Extract R from the signature made with the untampered-with keypair,
        // and add the same small torsion component to it as we did to the
        // tampered public key, and use the tampered R to create a malicious
        // additional signature.
        let mut ok_sig_r = [0u8; 32];
        ok_sig_r.copy_from_slice(&ok_sig.to_bytes()[..32]);

        let altered_sig_r = CompressedEdwardsY(ok_sig_r).decompress().unwrap() + torsion_component;
        let mut altered_sig_bytes = [0u8; 64];
        altered_sig_bytes[..32].copy_from_slice(altered_sig_r.compress().as_bytes());
        altered_sig_bytes[32..].copy_from_slice(&ok_sig.to_bytes()[32..]);
        let bad_sig = Signature::from_bytes(&altered_sig_bytes).unwrap();

        // The malicious signature will should not verify with the usual method:
        let single_res = pk_malicious.verify(&msg[..], &bad_sig);
        assert!(single_res.is_err());

        // It also should not verify with the strict checks:
        let strict_res = pk_malicious.verify_strict(&msg[..], &bad_sig);
        assert!(strict_res.is_err());

        let batch_res = verify_batch(&[&msg[..], &msg[..], &msg[..]],
                                     &[ok_sig, bad_sig, third_party_sig],
                                     &[keypair.public, pk_malicious, third_party_keypair.public]);

        // A set of malicious signatures constructed through an existing (sig,
        // msg, pk) triplet via adding small torsion components to the R portion
        // of the signature and the public key should result in an error.
        assert!(batch_res.is_err());
    }

    #[cfg(feature = "batch")]
    #[test]
    fn verify_batch_malleability_negation() {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::Scalar;
        use rand::rngs::OsRng;

        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        let msg = b"testing 1 2 3";

        // Make the same public key but negated.
        let pk_altered = keypair.public.to_bytes();
        let pk_altered_point = -CompressedEdwardsY(pk_altered).decompress().unwrap();
        let pk_malicious = PublicKey::from_bytes(&pk_altered_point.compress().to_bytes()).unwrap();

        // Make a completely unrelated, honest signer.
        let third_party_keypair = Keypair::generate(&mut csprng);
        let third_party_sig = third_party_keypair.sign(&msg[..]);

        // Sign the message with the untampered-with keypair.
        let ok_sig = keypair.sign(&msg[..]);

        // Extract s from the signature made with the untampered-with keypair,
        // negate it, and use the tampered s to create a malicious additional
        // signature.
        let mut ok_sig_s = [0u8; 32];
        ok_sig_s.copy_from_slice(&ok_sig.to_bytes()[32..]);

        let altered_sig_s = -Scalar::from_bits(ok_sig_s);
        let mut altered_sig_bytes = [0u8; 64];
        altered_sig_bytes[..32].copy_from_slice(altered_sig_s.as_bytes());
        altered_sig_bytes[32..].copy_from_slice(&ok_sig.to_bytes()[32..]);
        let bad_sig = Signature::from_bytes(&altered_sig_bytes).unwrap();

        // The malicious signature will not verify with the usual method:
        let single_res = pk_malicious.verify(&msg[..], &bad_sig);
        assert!(single_res.is_err());

        // It also should not verify with the strict checks:
        let strict_res = pk_malicious.verify_strict(&msg[..], &bad_sig);
        assert!(strict_res.is_err());

        let batch_res = verify_batch(&[&msg[..], &msg[..], &msg[..]],
                                     &[ok_sig, bad_sig, third_party_sig],
                                     &[keypair.public, pk_malicious, third_party_keypair.public]);

        // A set of malicious signatures constructed through an existing (sig,
        // msg, pk) triplet via adding small torsion components to the R portion
        // of the signature and the public key should result in an error.
        assert!(batch_res.is_err());
    }

    // XXX add test for Mikkel Fahnøe Jørgensen's attack: https://github.com/jedisct1/libsodium/issues/112
}

#[cfg(all(test, feature = "serde"))]
mod serialisation {
    use super::*;

    use self::bincode::{serialize, serialized_size, deserialize, Infinite};

    static PUBLIC_KEY_BYTES: [u8; PUBLIC_KEY_LENGTH] = [
        130, 039, 155, 015, 062, 076, 188, 063,
        124, 122, 026, 251, 233, 253, 225, 220,
        014, 041, 166, 120, 108, 035, 254, 077,
        160, 083, 172, 058, 219, 042, 086, 120, ];

    static SECRET_KEY_BYTES: [u8; SECRET_KEY_LENGTH] = [
        062, 070, 027, 163, 092, 182, 011, 003,
        077, 234, 098, 004, 011, 127, 079, 228,
        243, 187, 150, 073, 201, 137, 076, 022,
        085, 251, 152, 002, 241, 042, 072, 054, ];

    /// Signature with the above keypair of a blank message.
    static SIGNATURE_BYTES: [u8; SIGNATURE_LENGTH] = [
        010, 126, 151, 143, 157, 064, 047, 001,
        196, 140, 179, 058, 226, 152, 018, 102,
        160, 123, 080, 016, 210, 086, 196, 028,
        053, 231, 012, 157, 169, 019, 158, 063,
        045, 154, 238, 007, 053, 185, 227, 229,
        079, 108, 213, 080, 124, 252, 084, 167,
        216, 085, 134, 144, 129, 149, 041, 081,
        063, 120, 126, 100, 092, 059, 050, 011, ];

    #[test]
    fn serialize_deserialize_signature() {
        let signature: Signature = Signature::from_bytes(&SIGNATURE_BYTES).unwrap();
        let encoded_signature: Vec<u8> = serialize(&signature, Infinite).unwrap();
        let decoded_signature: Signature = deserialize(&encoded_signature).unwrap();

        assert_eq!(signature, decoded_signature);
    }

    #[test]
    fn serialize_deserialize_public_key() {
        let public_key: PublicKey = PublicKey::from_bytes(&PUBLIC_KEY_BYTES).unwrap();
        let encoded_public_key: Vec<u8> = serialize(&public_key, Infinite).unwrap();
        let decoded_public_key: PublicKey = deserialize(&encoded_public_key).unwrap();

        assert_eq!(&PUBLIC_KEY_BYTES[..], &encoded_public_key[encoded_public_key.len() - 32..]);
        assert_eq!(public_key, decoded_public_key);
    }

    #[test]
    fn serialize_deserialize_secret_key() {
        let secret_key: SecretKey = SecretKey::from_bytes(&SECRET_KEY_BYTES).unwrap();
        let encoded_secret_key: Vec<u8> = serialize(&secret_key, Infinite).unwrap();
        let decoded_secret_key: SecretKey = deserialize(&encoded_secret_key).unwrap();

        for i in 0..32 {
            assert_eq!(SECRET_KEY_BYTES[i], decoded_secret_key.as_bytes()[i]);
        }
    }

    #[test]
    fn serialize_public_key_size() {
        let public_key: PublicKey = PublicKey::from_bytes(&PUBLIC_KEY_BYTES).unwrap();
        assert_eq!(serialized_size(&public_key) as usize, 40); // These sizes are specific to bincode==1.0.1
    }

    #[test]
    fn serialize_signature_size() {
        let signature: Signature = Signature::from_bytes(&SIGNATURE_BYTES).unwrap();
        assert_eq!(serialized_size(&signature) as usize, 72); // These sizes are specific to bincode==1.0.1
    }

    #[test]
    fn serialize_secret_key_size() {
        let secret_key: SecretKey = SecretKey::from_bytes(&SECRET_KEY_BYTES).unwrap();
        assert_eq!(serialized_size(&secret_key) as usize, 40); // These sizes are specific to bincode==1.0.1
    }
}
