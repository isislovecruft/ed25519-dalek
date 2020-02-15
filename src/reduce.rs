// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! 2-dimensional lattice basis reduction based on Lagrange's algorithm.

use core::convert::TryFrom;
use core::ops::Mul;
use core::u64;

use byteorder::{ByteOrder, LittleEndian};

use crate::errors::InternalError;
use crate::errors::SignatureError;

/// A 255-bit signed integer, stored as 4 limbs of 64 bits each.
struct Integer255([u64; 4]);

impl<'a> TryFrom<&'a [u8]> for Integer255 {
    type Error = SignatureError;

    /// Attempt to decode these unsigned little-endian bytes into an `Integer255`.
    ///
    /// # Errors
    ///
    /// Returns a `Result` whose `Err` value is a `LatticeReductionError` if
    /// there were non-zero bits which could not fit into the `Integer255`.
    fn try_from(bytes: &[u8]) -> Result<Integer255, SignatureError> {
        let mut limbs: [u64; 4]= [0u64; 4];
        let l: usize = bytes.len();

        // Check that there are not extra bits which won't fit.
        if l > 32 || (bytes[l-1] & (1<<7) != 0) {
            return Err(SignatureError(InternalError::LatticeReductionError));
        }

        for i in 0..4 {
            limbs[i] = LittleEndian::read_u64(&bytes[i*8..i*8+8]);
        }

        Ok(Integer255(limbs))
    }
}

impl From<Integer255> for [u8; 32] {
    /// Decode an `Integer255` into an array of 32 bytes.
    fn from(integer: Integer255) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0u8; 32];

        LittleEndian::write_u64_into(&integer.0[..], &mut bytes);

        bytes
    }
}

/// A 510-bit signed integer, stored as 8 limbs of 64 bits each.
struct Integer510([u64; 8]);

impl<'a> TryFrom<&'a [u8]> for Integer510 {
    type Error = SignatureError;

    /// Attempt to decode these unsigned little-endian bytes into an `Integer510`.
    ///
    /// # Errors
    ///
    /// Returns a `Result` whose `Err` value is a `LatticeReductionError` if
    /// there were non-zero bits which could not fit into the `Integer255`.
    fn try_from(bytes: &[u8]) -> Result<Integer510, SignatureError> {
        let mut limbs: [u64; 8]= [0u64; 8];
        let l: usize = bytes.len();

        // Check that there are not extra bits which won't fit.
        if l > 64 || (bytes[l-1] & (1<<7) != 0) {
            return Err(SignatureError(InternalError::LatticeReductionError));
        }

        for i in 0..8 {
            limbs[i] = LittleEndian::read_u64(&bytes[i*8..i*8+8]);
        }

        Ok(Integer510(limbs))
    }
}

impl From<Integer510> for [u8; 64] {
    /// Decode an `Integer510` into an array of 64 bytes.
    fn from(integer: Integer510) -> [u8; 64] {
        let mut bytes: [u8; 64] = [0u8; 64];

        LittleEndian::write_u64_into(&integer.0[..], &mut bytes);

        bytes
    }
}

/// Helper function for widening 64 x 64 => 128 bit multiplication with casting.
fn m(a: u64, b: u64) -> u128 {
    a as u128 * b as u128
}

impl<'a, 'b> Mul<&'b Integer255> for &'a Integer255 {
    type Output = Integer510;

    /// Multiply two `Integer255`s into an `Integer510`.
    fn mul(self, b: &'b Integer255) -> Integer510 {
        let mut limbs: [u64; 8] = [0u64; 8];

        for i in 0..4 {
            let mut carry: u64 = 0;

            for j in 0..4 {
                let z: u128 = m(self.0[i], b.0[j]) + limbs[i+j] as u128 + carry as u128;

                limbs[i+j] = z as u64;
                carry = (z >> 64) as u64;
            }
            limbs[i+4] = carry;
        }

        Integer510(limbs)
    }
}

#[inline(always)]
fn overflowing_add(a: u64, b: u64) -> (u64, bool) {
    a.overflowing_add(b)
}

#[inline(always)]
fn overflowing_sub(a: u64, b: u64) -> (u64, bool) {
    a.overflowing_sub(b)
}

impl Integer255 {
    #[inline(always)]
    fn op_lshift<F>(a: &Integer255, b: &Integer255, shift: usize, op: F) -> Integer255
    where
        F: Fn(u64, u64) -> (u64, bool),
    {
        const SIZE: usize = 4;

        let mut shift: usize = shift;
        let mut limbs: [u64; SIZE] = [0u64; SIZE];
        let mut tmp_a: [u64; SIZE] = a.0;
        let mut tmp_b: [u64; SIZE] = b.0;

        if shift >= 64 {
            let k: usize = shift >> 6;
            
            shift &= 63;

            if k >= SIZE {
                return Integer255(limbs);
            }
            limbs[k] = tmp_b[SIZE-k];
            tmp_b = limbs;
        }

        let mut carry: bool;
        let mut product: u64 = 0;
        let mut shifted: u64 = 0;
        let mut remainder: u64 = 0;

        for i in 0..SIZE {
            shifted = tmp_b[i];

            if shift > 0 {
                shifted = (shifted << shift) | remainder;
            }

            let (product, carry) = op(tmp_a[i], shifted);
                
            if !carry {
                // If the carry flag wasn't set by the last operation, the
                // product is the actual product.
                limbs[i] = product;
            } else {
                // Otherwise it overflowed, so we know this product is the
                // maximum and we recursively deal with the carry in the
                // worst case.
                limbs[i] = u64::MAX;

                let mut j: usize = i+1;

                loop {
                    let (product, carry) = op(tmp_a[j], product);

                    if carry {
                        // If the result can't fit into the last limb we
                        // simply truncate the overflow.
                        tmp_a[j] = u64::MAX;
                    } else {
                        tmp_a[j] = product;
                        break;
                    }
                    if j < SIZE-1 {
                        j += 1;
                    } else {
                        break;
                    }
                }
            }
            if shift > 0 {
                remainder = shifted >> (64 - shift);
            }
        }
        Integer255(limbs)
    }

    pub fn add_lshift(a: &Integer255, b: &Integer255, shift: usize) -> Integer255 {
        Integer255::op_lshift(&a, &b, shift, overflowing_add)
    }

    pub fn sub_lshift(a: &Integer255, b: &Integer255, shift: usize) -> Integer255 {
        Integer255::op_lshift(&a, &b, shift, overflowing_sub)
    }
}

struct ReductionState {
    // XXX precompute and hardcode these
    modulus: Integer255,
    modulus_squared: Integer510,
    modulus_length:
}
