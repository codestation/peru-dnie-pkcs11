/// Parsed BER-TLV item.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    /// Numeric tag value. Multi-byte tags are packed in big-endian order.
    pub tag: u32,
    /// Value bytes, excluding tag and length.
    pub value: &'a [u8],
    /// Total encoded length of this TLV, including tag and length bytes.
    pub total_len: usize,
}

/// Parses one definite-length BER-TLV from the beginning of `input`.
pub fn parse_one(input: &[u8]) -> Option<Tlv<'_>> {
    if input.len() < 2 {
        return None;
    }
    let mut off = 1;
    let mut tag = input[0] as u32;
    if input[0] & 0x1f == 0x1f {
        tag = 0;
        loop {
            if off >= input.len() {
                return None;
            }
            let b = input[off];
            off += 1;
            tag = (tag << 8) | b as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    if off >= input.len() {
        return None;
    }
    let first_len = input[off];
    off += 1;
    let value_len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() || off + n > input.len() {
            return None;
        }
        let mut len = 0usize;
        for b in &input[off..off + n] {
            len = (len << 8) | *b as usize;
        }
        off += n;
        len
    };
    let end = off.checked_add(value_len)?;
    if end > input.len() {
        return None;
    }
    Some(Tlv {
        tag,
        value: &input[off..end],
        total_len: end,
    })
}

/// Returns the total encoded length of the first BER-TLV from a partial prefix.
///
/// The function returns `None` until the full tag and length fields are
/// available. The value bytes do not need to be present.
pub fn total_from_prefix(input: &[u8]) -> Option<usize> {
    if input.len() < 2 {
        return None;
    }
    let mut off = 1;
    if input[0] & 0x1f == 0x1f {
        loop {
            if off >= input.len() {
                return None;
            }
            let b = input[off];
            off += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    if off >= input.len() {
        return None;
    }
    let first_len = input[off];
    off += 1;
    let value_len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() || off + n > input.len() {
            return None;
        }
        let mut len = 0usize;
        for b in &input[off..off + n] {
            len = (len << 8) | *b as usize;
        }
        off += n;
        len
    };
    off.checked_add(value_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_form_tlv() {
        let tlv = parse_one(&[0x5A, 0x03, 1, 2, 3, 0xFF]).unwrap();
        assert_eq!(tlv.tag, 0x5A);
        assert_eq!(tlv.value, &[1, 2, 3]);
        assert_eq!(tlv.total_len, 5);
    }

    #[test]
    fn parses_long_form_length() {
        let input = [0x30, 0x81, 0x03, 1, 2, 3];
        assert_eq!(total_from_prefix(&input[..3]), Some(6));
        assert_eq!(parse_one(&input).unwrap().value, &[1, 2, 3]);
    }

    #[test]
    fn rejects_indefinite_or_truncated_lengths() {
        assert!(parse_one(&[0x30, 0x80]).is_none());
        assert!(parse_one(&[0x30, 0x02, 1]).is_none());
        assert!(total_from_prefix(&[0x30, 0x82, 0x01]).is_none());
    }
}
