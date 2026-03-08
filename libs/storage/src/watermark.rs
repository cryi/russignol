/// Size of a watermark file: level (4) + round (4) + blake3 (32)
pub const FILE_SIZE: usize = 40;

/// File names for each operation type, indexed by `OperationType as usize`
pub const FILENAMES: [&str; 3] = [
    "block_watermark",
    "preattestation_watermark",
    "attestation_watermark",
];

/// Encode a watermark entry as 40 bytes: level (4B BE) + round (4B BE) + blake3 (32B)
#[must_use]
pub fn encode(level: u32, round: u32) -> [u8; FILE_SIZE] {
    let mut buf = [0u8; FILE_SIZE];
    buf[0..4].copy_from_slice(&level.to_be_bytes());
    buf[4..8].copy_from_slice(&round.to_be_bytes());
    let hash = blake3::hash(&buf[0..8]);
    buf[8..40].copy_from_slice(hash.as_bytes());
    buf
}

/// Decode a 40-byte buffer into (level, round), validating the blake3 hash.
///
/// Returns `None` if the hash doesn't match.
#[must_use]
pub fn decode(buf: &[u8; FILE_SIZE]) -> Option<(u32, u32)> {
    let level = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let round = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let computed = blake3::hash(&buf[0..8]);
    if buf[8..40] != *computed.as_bytes() {
        return None;
    }
    Some((level, round))
}

/// Resolve what to write for a watermark slot given existing data and a minimum level.
///
/// - Existing data at or above `min_level`: preserved unchanged
/// - Existing data below `min_level`, corrupt, or wrong size: replaced with `encode(min_level, 0)`
/// - No existing data with a `min_level`: fresh `encode(min_level, 0)`
/// - No existing data and no minimum: `None` (nothing to write)
#[must_use]
pub fn effective_watermark(data: Option<&[u8]>, min_level: Option<u32>) -> Option<Vec<u8>> {
    match (data, min_level) {
        (Some(bytes), Some(min)) => {
            let level = bytes
                .try_into()
                .ok()
                .and_then(|buf: &[u8; FILE_SIZE]| decode(buf))
                .map(|(l, _)| l);
            match level {
                Some(l) if l >= min => Some(bytes.to_vec()),
                _ => Some(encode(min, 0).to_vec()),
            }
        }
        (Some(bytes), None) => Some(bytes.to_vec()),
        (None, Some(min)) => Some(encode(min, 0).to_vec()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let buf = encode(12345, 67);
        let (level, round) = decode(&buf).expect("Should decode valid entry");
        assert_eq!(level, 12345);
        assert_eq!(round, 67);
    }

    #[test]
    fn encode_decode_zero() {
        let buf = encode(0, 0);
        let (level, round) = decode(&buf).expect("Should decode zero entry");
        assert_eq!(level, 0);
        assert_eq!(round, 0);
    }

    #[test]
    fn encode_decode_max_values() {
        let buf = encode(u32::MAX, u32::MAX);
        let (level, round) = decode(&buf).expect("Should decode max entry");
        assert_eq!(level, u32::MAX);
        assert_eq!(round, u32::MAX);
    }

    #[test]
    fn corrupted_hash_returns_none() {
        let mut buf = encode(100, 5);
        buf[39] ^= 0xFF;
        assert!(decode(&buf).is_none(), "Bad hash should be rejected");
    }

    #[test]
    fn effective_watermark_preserves_data_above_min() {
        let data = encode(200_000, 5).to_vec();
        let result = effective_watermark(Some(&data), Some(100_000));
        assert_eq!(result.as_ref().unwrap().as_slice(), data.as_slice());
    }

    #[test]
    fn effective_watermark_replaces_data_below_min() {
        let data = encode(100_000, 5).to_vec();
        let result = effective_watermark(Some(&data), Some(200_000)).unwrap();
        let buf: &[u8; FILE_SIZE] = result.as_slice().try_into().unwrap();
        assert_eq!(decode(buf), Some((200_000, 0)));
    }

    #[test]
    fn effective_watermark_creates_from_min_when_missing() {
        let result = effective_watermark(None, Some(150_000)).unwrap();
        let buf: &[u8; FILE_SIZE] = result.as_slice().try_into().unwrap();
        assert_eq!(decode(buf), Some((150_000, 0)));
    }

    #[test]
    fn effective_watermark_none_when_both_absent() {
        assert!(effective_watermark(None, None).is_none());
    }

    #[test]
    fn effective_watermark_replaces_corrupt_data() {
        let mut data = encode(100_000, 0).to_vec();
        data[39] ^= 0xFF;
        let result = effective_watermark(Some(&data), Some(150_000)).unwrap();
        let buf: &[u8; FILE_SIZE] = result.as_slice().try_into().unwrap();
        assert_eq!(decode(buf), Some((150_000, 0)));
    }

    #[test]
    fn effective_watermark_replaces_wrong_size_data() {
        let result = effective_watermark(Some(&[1, 2, 3]), Some(150_000)).unwrap();
        let buf: &[u8; FILE_SIZE] = result.as_slice().try_into().unwrap();
        assert_eq!(decode(buf), Some((150_000, 0)));
    }

    #[test]
    fn effective_watermark_passes_through_without_min() {
        let data = encode(100_000, 5).to_vec();
        let result = effective_watermark(Some(&data), None);
        assert_eq!(result.as_ref().unwrap().as_slice(), data.as_slice());
    }
}
