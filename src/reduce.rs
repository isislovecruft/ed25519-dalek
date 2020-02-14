// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! 2-dimensional lattice basis reduction based on Lagrange's algorithm.

use byteorder::{ByteOrder, LittleEndian};

use crate::errors::LatticeReductionError;

/// A 255-bit signed integer, stored as 4 limbs of 64 bits each.
type Integer255([u64; 4]);

impl<'a> TryFrom<&'a [u8] for Integer255 {
    /// Attempt to decode these unsigned little-endian bytes into an `Integer255`.
    ///
    /// # Errors
    ///
    /// Returns a `Result` whose `Err` value is a `LatticeReductionError` if
    /// there were non-zero bits which could not fit into the `Integer255`.
    fn try_from(bytes: &[u8]) -> Result<Integer255, LatticeReductionError> {
        let mut limbs: [u64; 4]= [0u64; 4];
        let h: usize = 0;
        let l: usize = bytes.len();

        // Check that there are not extra bits which won't fit.
        if l > 32 || bytes[l-1] & (1<<7) { // XXX Am I checking the correct bit here?
            return Err(LatticeReductionError);
        }

        'outer: for i in 0..4 {
            'inner: for j in 0..8 {
                // Check if we ran out of bytes to process.
                if h+j == l { break 'outer; }

                limbs[i] += bytes[h+j] << j*8;
            }
            h += 8;
        }
        Ok(Integer255(limbs))
    }
}

impl From<Integer255> for [u8; 32] {
    /// Decode an `Integer255` into an array of 32 bytes.
    fn from(integer: Integer255) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0u8; 32];
        let limbs: [u64; 4] = integer.0;

        LittleEndian::write_u64_into(&integer.0[..], &bytes);

        bytes
    }
}

impl Integer255 {

}

/// A 510-bit signed integer, stored as 8 limbs of 64 bits each.
type Integer510([u64; 8]);
