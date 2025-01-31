// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::structures::MaxBuffer;
use tss_esapi::tss2_esys::{TPM2B_MAX_BUFFER, TPM2_MAX_DIGEST_BUFFER};

mod test_auth {
    use super::*;

    const ABOVE_MAX: usize = TPM2_MAX_DIGEST_BUFFER as usize + 1;

    #[test]
    fn test_max_sized_data() {
        let _ = MaxBuffer::try_from([0xff; TPM2_MAX_DIGEST_BUFFER as usize].to_vec()).unwrap();
    }

    #[test]
    fn test_to_large_data() {
        let _ = MaxBuffer::try_from([0xff; ABOVE_MAX].to_vec()).unwrap_err();
    }

    #[test]
    fn test_default() {
        {
            let max_buffer: MaxBuffer = Default::default();
            let expected: TPM2B_MAX_BUFFER = Default::default();
            let actual = TPM2B_MAX_BUFFER::try_from(max_buffer).unwrap();
            assert_eq!(expected.size, actual.size);
            assert_eq!(
                expected.buffer.len(),
                actual.buffer.len(),
                "Buffers don't have the same length"
            );
            assert!(
                expected
                    .buffer
                    .iter()
                    .zip(actual.buffer.iter())
                    .all(|(a, b)| a == b),
                "Buffers are not equal"
            );
        }
        {
            let tss_max_buffer: TPM2B_MAX_BUFFER = Default::default();
            let expected: MaxBuffer = Default::default();
            let actual = MaxBuffer::try_from(tss_max_buffer).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_as_ref() {
        // The following function accepts the broadest selection of types as its argument
        // including MaxBuffer. It also returns the MaxBuffer but in such a way that the
        // client is not aware of the true underlying type.
        fn accepts_returns_as_ref(data: impl AsRef<[u8]>) -> tss_esapi::Result<impl AsRef<[u8]>> {
            let data = data.as_ref();
            let max_buffer = MaxBuffer::from_bytes(data)?;
            Ok(max_buffer)
        }
        accepts_returns_as_ref(MaxBuffer::from_bytes(&[1, 2, 3]).unwrap()).unwrap();
    }
}
