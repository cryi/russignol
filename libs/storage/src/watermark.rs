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
}
