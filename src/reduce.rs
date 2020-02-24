// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! 2-dimensional lattice basis reduction based on Lagrange's algorithm.

use alloc::vec::Vec;

use core::convert::TryFrom;
use core::ops::Mul;
use core::u64;

use byteorder::{ByteOrder, LittleEndian};

use crate::errors::InternalError;
use crate::errors::SignatureError;

/// A 255-bit signed integer, stored as 4 limbs of 64 bits each.
#[derive(Debug)]
pub(crate) struct Integer255([u64; 4]);

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
#[derive(Debug)]
pub(crate) struct Integer510([u64; 8]);

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

/// Add-with-carry two slices of u64s, a and b, into the sum c.
fn addcarry_u64s<'a, 'b, 'c>(carry_in: u64, a: &'a [u64], b: &'b [u64], c: &mut [u64]) -> bool {
    let mut carry: bool = false;
    let mut product: u64 = 0;

    debug_assert!(a.len() == b.len());

    let mut tmp_a = Vec:: a.clone();
    let size: usize = a.len();

    for i in 0..size {
        let (product, carry) = tmp_a[i].overflowing_add(b[i]);
                
        if !carry {
            // If the carry flag wasn't set by the last operation, the
            // product is the actual product.
            c[i] = product;
        } else {
            // Otherwise it overflowed, so we know this product is the
            // maximum and we recursively deal with the carry in the
            // worst case.
            c[i] = u64::MAX;

            let mut j: usize = i+1;

            loop {
                let (product, carry) = tmp_a[j].overflowing_add(product);

                if carry {
                    // If the result can't fit into the last limb we
                    // simply truncate the overflow.
                    tmp_a[j] = u64::MAX;
                } else {
                    tmp_a[j] = product;
                    break;
                }
                if j < size-1 {
                    j += 1;
                } else {
                    break;
                }
            }
        }
    }
    carry // true if truncation occurred, false otherwise.
}

/// Subtract-with-borrow two slices of u64s, a and b, into the difference c.
fn subborrow_u64s<'a, 'b, 'c>(carry_in: u64, a: &'a [u64], b: &'b [u64], c: &mut [u64]) -> bool {
    let mut carry: bool = false;
    let mut difference: u64 = 0;

    debug_assert!(a.len() == b.len());

    let mut tmp_a = a.clone();
    let size: usize = a.len();

    for i in 0..size {
        let (difference, carry) = tmp_a[i].overflowing_sub(b[i]);
                
        if !carry {
            // If the carry flag wasn't set by the last operation, the
            // product is the actual product.
            c[i] = difference;
        } else {
            // Otherwise it underflowed, so we know this difference is the
            // minimum and we recursively deal with the carry in the
            // worst case.
            c[i] = u64::MIN;

            let mut j: usize = i+1;

            loop {
                let (difference, carry) = tmp_a[j].overflowing_sub(difference);

                if carry {
                    // If the result can't fit into the last limb we
                    // simply truncate the overflow.
                    tmp_a[j] = u64::MIN;
                } else {
                    tmp_a[j] = difference;
                    break;
                }
                if j < size-1 {
                    j += 1;
                } else {
                    break;
                }
            }
        }
    }
    carry // true if truncation occurred, false otherwise.
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
    pub fn zero() -> Integer255 {
        Integer255([ 0, 0, 0, 0, ])
    }

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

// XXX figure out a way to macro-ise this
impl Integer510 {
    #[inline(always)]
    fn op_lshift<F>(a: &Integer510, b: &Integer510, shift: usize, op: F) -> Integer510
    where
        F: Fn(u64, u64) -> (u64, bool),
    {
        const SIZE: usize = 8;

        let mut shift: usize = shift;
        let mut limbs: [u64; SIZE] = [0u64; SIZE];
        let mut tmp_a: [u64; SIZE] = a.0;
        let mut tmp_b: [u64; SIZE] = b.0;

        if shift >= 64 { // XXX not sure about this squaring
            let k: usize = shift >> 6;
            
            shift &= 63;

            if k >= SIZE {
                return Integer510(limbs); // XXX this should be a compile-time error
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
        Integer510(limbs)
    }

    pub fn add_lshift(a: &Integer510, b: &Integer510, shift: usize) -> Integer510 {
        Integer510::op_lshift(&a, &b, shift, overflowing_add)
    }

    pub fn sub_lshift(a: &Integer510, b: &Integer510, shift: usize) -> Integer510 {
        Integer510::op_lshift(&a, &b, shift, overflowing_sub)
    }
}

#[derive(Debug)] // XXX remove the derive
pub(crate) struct ReductionState {
    // XXX precompute and hardcode these
    modulus: Integer255,
    modulus_squared: Integer510,
    modulus_length: usize,
    target_length: usize,
}

// XXX We don't need this code since we only operate over one fixed
// modulus, but keep it around until we're positive the generated
// values match.
impl ReductionState {
    fn new(modulus: &[u8]) -> Result<ReductionState, SignatureError> {
        let mod_len: usize = modulus.len();

        // Check that the modulus is within the supported range.
        // XXX Switch to only allowing [u8;32], not &[u8]
        if mod_len > 32 {
            return Err(SignatureError(InternalError::LatticeReductionError));
        }

        // Check that the higest bit is unset (we only support 255-bit
        // integers for the modulus).
        if mod_len == 32 && modulus[31] >= 0x80 {
            return Err(SignatureError(InternalError::LatticeReductionError));
        }

        let ell: Integer255 = Integer255::try_from(modulus)?;
        let ell_squared: Integer510 = &ell * &ell;

        // XXX k is hardcoded

        // If k = bitlength(n) == 253, then the target bit length is k+1, and
        // output values are smaller (in absolute value) than sqrt(2^(k+1)).
        let target_length: usize = (((253 + 2) >> 1) + 8) >> 3;

        Ok(ReductionState {
            modulus: ell,
            modulus_squared: ell_squared,
            modulus_length: 253,
            target_length: target_length,
        })
    }
}

const ELL_BYTES: [u8; 32] = [
	0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
	0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
];

/// ell is the order of the ed25519 basepoint.
const ELL: Integer255 = Integer255([6346243789798364141,
                                    1503914060200516822,
                                    0,
                                    1152921504606846976]);

/// This is ell * ell.
const ELL_SQUARED: Integer510 = Integer510([16351996876013341033,
                                            7494995240958862109,
                                            4453757063706179006,
                                            11651825165850652826,
                                            14628338529006959229,
                                            187989257525064602,
                                            0,
                                            72057594037927936]);

/// If k = bitlength(ell) == 253, then the target bitlength is k+1, and
/// output values are smaller (in absolute value) than sqrt(2^(k+1)).
const ELL_BITLENGTH: usize = 253;

/// The size in bytes of a reduced basis.
const REDUCED_BITLENGTH: usize = 16;

/// Perform basis reduction: given integer b, this function returns
/// _signed_ integers c0 and c1 such that:
///   c0 = c1*b mod n
///   |c0| < 2^((k+1)/2)
///   |c1| < 2^((k+1)/2)
/// where n is the modulus initialized in the provided state, and k is
/// the bit length of n (i.e. 2^(k-1) < n < 2^k). The source integer b
/// MUST be between 1 and n-1.
///
/// The common size of c0 and c1, in bytes, is returned; that size is
/// ceil((ceil((k+1)/2)+8)/8), i.e. the smallest size that can contain all
/// possible c0 and c1 values (given the initialized modulus), including
/// the sign bit: c0 and c1 are signed integers, they can be negative.
///
/// On error, 0 is returned. An error is reported if b is zero or is
/// not lower than n. There might be other rare error conditions, in
/// particular if GCD(b,n) != 1.
/// (It is currently unclear whether the algorithm can ever hit an error
/// condition when n is prime and 0 < b < n.)
pub(crate) fn reduce_basis(state: ReductionState, integer: Integer255)
    -> Result<(Integer255, Integer255), SignatureError>
{
    // Initialisation:
    //   u = [ell,     0]
    //   v = [integer, 1]
    let u0_0 = ELL.0[0];
    let u0_1 = ELL.0[1];
    let u0_2 = ELL.0[2];
    let u0_3 = ELL.0[3];

    let u1_0 = 0u64;
    let u1_1 = 0u64;
    let u1_2 = 0u64;
    let u1_3 = 0u64;

    // Also check that integer < ell.
    let v0_0 = integer.0[0];
    let v0_1 = integer.0[1];
    let v0_2 = integer.0[2];
    let v0_3 = integer.0[3];
    
    //let

    unimplemented!();
}

#[cfg(test)]
mod test {
    use super::*;

    const INTEGER255_TWO: [u8; 32] = [ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ];
    const INTEGER255_MAX: [u8; 32] = [ 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
                                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
                                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
                                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, ];

    #[test]
    fn reduction_state() {
        let state: ReductionState = ReductionState::new(&ELL_BYTES[..]).unwrap();

        println!("{:?}", state);
    }

    #[test]
    fn decode_encode_modulus() {
        let decoded: Integer255 = Integer255::try_from(&ELL_BYTES[..]).unwrap();
        let encoded: [u8; 32] = decoded.into();

        assert_eq!(&ELL_BYTES, &encoded);
    }

    #[test]
    fn addcarry_u64s_overflow() {
        let a = Integer255::try_from(&INTEGER255_MAX[..]).unwrap(); // 2^255 - 1 
        let b = Integer255::try_from(&INTEGER255_TWO[..]).unwrap(); // 2
        let mut c = Integer255::zero();
        let mut d = Integer255::zero();
        let mut r = addcarry_u64s(0, &a.0, &a.0, &mut c.0); // (2^255 - 1)*2
        let mut s = addcarry_u64s(0, &c.0, &b.0, &mut d.0); // (2^255 - 1)*2 + 2 == (2**256)

        assert!(s); // overflow should have happened and one bit should have been truncated
        assert!(c.0 == [u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
    }
}
