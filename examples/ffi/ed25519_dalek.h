// -*- mode: c; -*-
//
// To the extent possible under law, the authors have waived all copyright and
// related or neighboring rights to curve25519-dalek, using the Creative
// Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/.0/> for full details.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

typedef struct ed25519_dalek_public_key_s {
  uint8_t bytes[32];
} ed25519_dalek_public_key_t;

typedef struct ed25519_dalek_secret_key_s {
  uint8_t bytes[64];
} ed25519_dalek_secret_key_t;

typedef struct ed25519_dalek_keypair_s {
  ed25519_dalek_public_key_t public;
  ed25519_dalek_secret_key_t secret;
} ed25519_dalek_keypair_t;

typedef struct ed25519_dalek_signature_s {
  uint8_t bytes[64];
} ed25519_dalek_signature_t;

extern ed25519_dalek_keypair_t ed25519_dalek_keypair_generate();
extern ed25519_dalek_signature_t ed25519_dalek_sign(const ed25519_dalek_secret_key_t* secret_key,
                                                    const uint8_t* message,
                                                    const size_t message_len);
extern uint8_t ed25519_dalek_verify(const ed25519_dalek_public_key_t* public_key,
                                    const uint8_t* message,
                                    const size_t message_len,
                                    const ed25519_dalek_signature_t* signature);
