// -*- mode: rust; -*-
//
// To the extent possible under law, the authors have waived all copyright and
// related or neighboring rights to curve25519-dalek, using the Creative
// Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/.0/> for full details.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

//! Foreign Function Interface API, for key generation, signing, and
//! verification in other languages.
//!
//! # Headers
//!
//! For convenience, the following C/C++ structs and declarations are included
//! in `.../examples/ffi/ed25519_dalek.h` (from the top directory of this
//! repository):
//!
//! ```c
//! typedef struct ed25519_dalek_public_key_s {
//!   uint8_t bytes[32];
//! } ed25519_dalek_public_key_t;
//!
//! typedef struct ed25519_dalek_secret_key_s {
//!   uint8_t bytes[64];
//! } ed25519_dalek_secret_key_t;
//!
//! typedef struct ed25519_dalek_keypair_s {
//!   public_key_t public;
//!   secret_key_t secret;
//! } ed25519_dalek_keypair_t;
//!
//! typedef struct ed25519_dalek_signature_s {
//!   uint8_t bytes[64];
//! } ed25519_dalek_signature_t;
//!
//! extern ed25519_dalek_keypair_t ed25519_dalek_keypair_generate();
//! extern ed25519_dalek_signature_t sign(const ed25519_dalek_secret_key_t* secret_key,
//!                                       const uint8_t* message,
//!                                       const size_t message_len);
//! extern uint8_t ed25519_dalek_verify(const ed25519_dalek_public_key_t* public_key,
//!                                     const uint8_t* message,
//!                                     const size_t message_len,
//!                                     const ed25519_dalek_signature_t* signature);
//! ```
//!
//! # Examples
//!
//! ```c
//! #include <assert.h>
//! #include <stdint.h>
//! #include "ed25519_dalek.h"
//!
//! void main() {
//!   ed25519_dalek_keypair_t keypair;
//!   ed25519_dalek_signature_t signature;
//!
//!   uint8_t  good_sig;
//!   uint8_t* message = "This is a test of the tsunami alert system.";
//!   size_t   message_len = sizeof(message);
//!
//!   keypair   = ed25519_dalek_keypair_generate();
//!   signature = ed25519_dalek_sign(&keypair.secret, message, message_len);
//!   good_sig  = ed25519_dalek_verify(&keypair.public, message, message_len, &signature);
//!
//!   assert(good_sig);
//! }
//! ```
//!
//! The code for the above example is contained within
//! `.../examples/ffi/ed25519_dalek_test.c`.  To compile it, go to the
//! `.../examples/ffi` directory and do:
//!
//! ```shell
//! cargo install --features="nightly ffi"
//! make && ./ed25519_dalek_test
//! ```

use sha2::Sha512;
use rand::OsRng;
use libc::{uint8_t, size_t};
use core::slice;

use ed25519::Keypair;
use ed25519::PublicKey;
use ed25519::SecretKey;
use ed25519::Signature;

#[cfg(not(feature = "std"))]
pub extern fn fix_linking_when_using_no_std() { panic!() }

macro_rules! ptr_to_slice {
    ( $msg:expr, $len:expr ) => {{
        // Rust references may never be NULL
        assert!(!$msg.is_null());
        // Convert from pointer and length to a slice. This is unsafe,
        // as we may be dereferencing invalid memory.
        unsafe {
            slice::from_raw_parts($msg, $len as usize)
        }
    }}
}

macro_rules! ptr_to_struct {
    ( $key:expr ) => {{
        // Rust references may never be NULL
        assert!(!$key.is_null());
        // Dereference the pointer to obtain the underlying struct. This allows
        // us to share const pointers between C and Rust.
        unsafe {
            &*$key
        }
    }}
}

#[no_mangle]
/// Generate a keypair for use in a foreign language.
pub extern fn ed25519_dalek_keypair_generate() -> Keypair {
    let mut csprng: OsRng = OsRng::new().unwrap();

    Keypair::generate::<Sha512>(&mut csprng)
}

#[no_mangle]
/// Given a `secret_key`, sign a `message` in a foreign language.
pub unsafe extern fn ed25519_dalek_sign(secret_key: *const SecretKey,
                                        message: *const uint8_t,
                                        message_len: size_t) -> Signature {
    let msg = ptr_to_slice!(message, message_len);
    let sk =  ptr_to_struct!(secret_key);

    sk.sign::<Sha512>(msg)
}

#[no_mangle]
/// Given a `public_key`, a `signature`, and a `message`, verify the `signature`.
pub unsafe extern fn ed25519_dalek_verify(public_key: *const PublicKey,
                                          message: *const uint8_t,
                                          message_len: size_t,
                                          signature: *const Signature) -> uint8_t {
    let msg = ptr_to_slice!(message, message_len);
    let pk =  ptr_to_struct!(public_key);
    let sig = ptr_to_struct!(signature);

    let r = pk.verify::<Sha512>(msg, sig);

    if r {
        return 1u8 as uint8_t;
    } else {
        return 0u8 as uint8_t;
    }
}
