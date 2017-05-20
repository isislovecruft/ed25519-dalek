// -*- mode: c; -*-
//
// To the extent possible under law, the authors have waived all copyright and
// related or neighboring rights to curve25519-dalek, using the Creative
// Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/.0/> for full details.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

/**
 * Test code for creating a keypair, then signing/verifying a message, from C.
 */

#include <stdio.h>
#include <stdint.h>

#include "ed25519_dalek.h"

static void print_bytes(uint8_t* key, size_t len, char* structname) {
  uint8_t i;

  printf("%s([ ", structname);
  for (i=0; i<len; i++) {
    printf("0x%X, ", key[i]);
  }
  printf("])\n");
}

void main() {
  ed25519_dalek_keypair_t   keypair;
  ed25519_dalek_signature_t signature;
  uint8_t  good_sig;
  uint8_t* message;
  size_t   message_len;

  message = "This is a test of the tsunami alert system.";
  message_len = sizeof(message);

  keypair = ed25519_dalek_keypair_generate();
  print_bytes(keypair.public.bytes, sizeof(keypair.public.bytes), "PublicKey");
  print_bytes(keypair.secret.bytes, sizeof(keypair.secret.bytes), "SecretKey");

  signature = ed25519_dalek_sign(&keypair.secret, message, message_len);
  print_bytes(signature.bytes, sizeof(signature.bytes), "Signature");

  good_sig = ed25519_dalek_verify(&keypair.public, message, message_len, &signature);

  if (good_sig) {
    printf("Good signature!\n");
  } else {
    printf("Bad signature!\n");
  }
}
