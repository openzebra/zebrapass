use subtle::ConstantTimeEq;

/// Constant-time equality of two 32-byte values.
#[must_use]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::ct_eq_32;

    #[test]
    fn equal_inputs_match() {
        let left = [0x5Au8; 32];
        let right = [0x5Au8; 32];
        assert!(ct_eq_32(&left, &right));
    }

    #[test]
    fn one_bit_difference_does_not_match() {
        let left = [0x5Au8; 32];
        let mut right = left;
        if let Some(first) = right.first_mut() {
            *first ^= 1;
        }
        assert!(!ct_eq_32(&left, &right));
    }
}
