// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! 26-bit message sequence number with wrapping.
//!
//! Message numbers in SRT use 26 bits (bits 0-25 of the MSGNO header field).
//! The upper bits encode packet boundary, order flag, encryption key spec,
//! and retransmission flag.

/// Maximum value of a 26-bit message number.
pub const MAX_MSG_SEQ: u32 = 0x03FF_FFFF; // 2^26 - 1

/// A 26-bit circular message number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MsgNo(u32);

impl MsgNo {
    /// Create a new message number. Value is masked to 26 bits.
    /// Message numbers start at 1 (0 is reserved).
    #[inline]
    pub fn new(val: u32) -> Self {
        let masked = val & MAX_MSG_SEQ;
        Self(if masked == 0 { 1 } else { masked })
    }

    /// Get the raw 26-bit value.
    #[inline]
    pub fn value(self) -> u32 {
        self.0
    }

    /// Increment the message number by 1, wrapping at MAX_MSG_SEQ.
    /// Skips 0 (message numbers range from 1 to MAX_MSG_SEQ).
    #[inline]
    pub fn increment(self) -> Self {
        let next = if self.0 >= MAX_MSG_SEQ { 1 } else { self.0 + 1 };
        Self(next)
    }
}

impl std::fmt::Display for MsgNo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for MsgNo {
    fn from(val: u32) -> Self {
        Self::new(val)
    }
}

impl From<MsgNo> for u32 {
    fn from(msg: MsgNo) -> u32 {
        msg.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_masks() {
        assert_eq!(MsgNo::new(1).value(), 1);
        assert_eq!(MsgNo::new(MAX_MSG_SEQ).value(), MAX_MSG_SEQ);
        // 0 wraps to 1
        assert_eq!(MsgNo::new(0).value(), 1);
    }

    #[test]
    fn test_increment_wrap() {
        assert_eq!(MsgNo::new(1).increment(), MsgNo::new(2));
        assert_eq!(MsgNo::new(MAX_MSG_SEQ).increment(), MsgNo::new(1));
    }
}
