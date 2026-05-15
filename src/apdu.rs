/// Encodes a short ISO 7816 command APDU.
///
/// Extended-length APDUs are intentionally not produced here because the DNIe
/// operations used by this module fit in short APDUs. Sensitive payloads passed
/// to this function must not be logged by callers.
pub fn encode(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    le: Option<u32>,
) -> Result<Vec<u8>, ()> {
    if data.len() > 255 || le.is_some_and(|v| v > 256) {
        return Err(());
    }
    let mut out = Vec::with_capacity(5 + data.len() + usize::from(le.is_some()));
    out.extend_from_slice(&[cla, ins, p1, p2]);
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    if let Some(le) = le {
        out.push(if le == 256 { 0 } else { le as u8 });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_case_1_apdu() {
        assert_eq!(encode(0, 0xA4, 4, 0, &[], None), Ok(vec![0, 0xA4, 4, 0]));
    }

    #[test]
    fn encodes_data_and_le() {
        assert_eq!(
            encode(0, 0xA4, 4, 0, &[0x3F, 0x00], Some(256)),
            Ok(vec![0, 0xA4, 4, 0, 2, 0x3F, 0x00, 0])
        );
    }

    #[test]
    fn rejects_extended_lengths() {
        assert!(encode(0, 0, 0, 0, &[0; 256], None).is_err());
        assert!(encode(0, 0, 0, 0, &[], Some(257)).is_err());
    }
}
