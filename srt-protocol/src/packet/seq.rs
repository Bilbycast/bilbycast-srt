// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! 31-bit circular sequence number arithmetic for SRT packets.
//!
//! SRT uses 31-bit sequence numbers (bit 31 is reserved for the control flag).
//! The sequence space wraps around: after `MAX_SEQ` (0x7FFFFFFF), the next
//! sequence number is 0.
//!
//! Comparisons account for wraparound: two sequence numbers that differ by
//! more than half the sequence space are considered to have wrapped around.

/// Maximum value of a 31-bit sequence number.
pub const MAX_SEQ: i32 = 0x7FFF_FFFF;

/// Half the sequence number space, used for wraparound comparison.
const HALF_SEQ: i32 = (MAX_SEQ / 2) + 1;

/// A 31-bit circular sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeqNo(i32);

impl SeqNo {
    /// Create a new sequence number from a raw 31-bit value.
    /// The value is masked to 31 bits.
    #[inline]
    pub fn new(val: i32) -> Self {
        Self(val & MAX_SEQ)
    }

    /// Get the raw 31-bit value.
    #[inline]
    pub fn value(self) -> i32 {
        self.0
    }

    /// Increment the sequence number by 1, wrapping at MAX_SEQ.
    #[inline]
    pub fn increment(self) -> Self {
        Self::new(if self.0 == MAX_SEQ { 0 } else { self.0 + 1 })
    }

    /// Decrement the sequence number by 1, wrapping at 0.
    #[inline]
    pub fn decrement(self) -> Self {
        Self::new(if self.0 == 0 { MAX_SEQ } else { self.0 - 1 })
    }

    /// Add an offset to the sequence number with wrapping.
    #[inline]
    pub fn add(self, offset: i32) -> Self {
        Self::new(((self.0 as i64 + offset as i64) % (MAX_SEQ as i64 + 1)) as i32)
    }

    /// Compute the signed difference `self - other` in the circular sequence space.
    ///
    /// Returns a value in the range `(-HALF_SEQ, HALF_SEQ]`.
    /// Positive means `self` is ahead of `other`.
    #[inline]
    pub fn diff(self, other: SeqNo) -> i32 {
        let d = (self.0 as i64 - other.0 as i64) as i32;
        if d.abs() < HALF_SEQ {
            d
        } else if d < 0 {
            d + MAX_SEQ + 1
        } else {
            d - MAX_SEQ - 1
        }
    }

    /// Check if `self` is after `other` in the circular sequence space.
    #[inline]
    pub fn is_after(self, other: SeqNo) -> bool {
        self.diff(other) > 0
    }

    /// Check if `self` is before `other` in the circular sequence space.
    #[inline]
    pub fn is_before(self, other: SeqNo) -> bool {
        self.diff(other) < 0
    }

    /// Compute the offset from `start` to `end` (non-negative distance going forward).
    /// Returns a value in `[0, MAX_SEQ]`.
    #[inline]
    pub fn offset(start: SeqNo, end: SeqNo) -> i32 {
        let d = end.diff(start);
        if d >= 0 {
            d
        } else {
            d + MAX_SEQ + 1
        }
    }
}

impl std::fmt::Display for SeqNo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<i32> for SeqNo {
    fn from(val: i32) -> Self {
        Self::new(val)
    }
}

impl From<SeqNo> for i32 {
    fn from(seq: SeqNo) -> i32 {
        seq.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment() {
        assert_eq!(SeqNo::new(0).increment(), SeqNo::new(1));
        assert_eq!(SeqNo::new(MAX_SEQ).increment(), SeqNo::new(0));
    }

    #[test]
    fn test_decrement() {
        assert_eq!(SeqNo::new(1).decrement(), SeqNo::new(0));
        assert_eq!(SeqNo::new(0).decrement(), SeqNo::new(MAX_SEQ));
    }

    #[test]
    fn test_diff_no_wrap() {
        let a = SeqNo::new(100);
        let b = SeqNo::new(50);
        assert_eq!(a.diff(b), 50);
        assert_eq!(b.diff(a), -50);
    }

    #[test]
    fn test_diff_with_wrap() {
        let a = SeqNo::new(10);
        let b = SeqNo::new(MAX_SEQ - 10);
        // a is 21 steps ahead of b (wrapping forward)
        assert_eq!(a.diff(b), 21);
        assert_eq!(b.diff(a), -21);
    }

    #[test]
    fn test_is_after() {
        assert!(SeqNo::new(100).is_after(SeqNo::new(50)));
        assert!(!SeqNo::new(50).is_after(SeqNo::new(100)));
        // Wrap case
        assert!(SeqNo::new(5).is_after(SeqNo::new(MAX_SEQ - 5)));
    }

    #[test]
    fn test_offset() {
        assert_eq!(SeqNo::offset(SeqNo::new(10), SeqNo::new(20)), 10);
        assert_eq!(
            SeqNo::offset(SeqNo::new(MAX_SEQ - 5), SeqNo::new(5)),
            11
        );
    }

    #[test]
    fn test_add() {
        assert_eq!(SeqNo::new(10).add(5), SeqNo::new(15));
        assert_eq!(SeqNo::new(MAX_SEQ - 2).add(5), SeqNo::new(2));
    }
}
