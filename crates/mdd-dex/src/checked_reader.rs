use mdd_types::{ErrorCode, MddError, MddResult};

#[derive(Clone, Copy)]
pub struct CheckedReader<'a> {
    bytes: &'a [u8],
}

pub(crate) fn invalid(reason: &str, stage: &str, offset: u64, length: u64) -> MddError {
    MddError::new(ErrorCode::InvalidInput, stage, reason)
        .detail("reason", reason)
        .detail("byte_offset", offset.to_string())
        .detail("byte_length", length.to_string())
        .detail("input_coverage", "partial")
        .detail("facts_coverage", "unknown")
        .detail("source_binding", "caller_snapshot_required")
}

impl<'a> CheckedReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn range(&self, offset: u64, length: u64) -> MddResult<&'a [u8]> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("RANGE_OVERFLOW", "dex.checked_reader", offset, length))?;
        if end > self.len() {
            return Err(
                invalid("TRUNCATED_RANGE", "dex.checked_reader", offset, length)
                    .detail("available_bytes", self.len().to_string()),
            );
        }
        let start = usize::try_from(offset)
            .map_err(|_| invalid("HOST_RANGE_OVERFLOW", "dex.checked_reader", offset, length))?;
        let end = usize::try_from(end)
            .map_err(|_| invalid("HOST_RANGE_OVERFLOW", "dex.checked_reader", offset, length))?;
        self.bytes
            .get(start..end)
            .ok_or_else(|| invalid("TRUNCATED_RANGE", "dex.checked_reader", offset, length))
    }

    pub fn array(&self, offset: u64, count: u64, stride: u64) -> MddResult<&'a [u8]> {
        let length = count.checked_mul(stride).ok_or_else(|| {
            invalid("COUNT_STRIDE_OVERFLOW", "dex.checked_reader", offset, count)
                .detail("stride", stride.to_string())
        })?;
        self.range(offset, length)
    }

    pub fn u16(&self, offset: u64) -> MddResult<u16> {
        let bytes = self.range(offset, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn u32(&self, offset: u64) -> MddResult<u32> {
        let bytes = self.range(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_and_ranges_reject_before_reading() {
        let reader = CheckedReader::new(&[1, 2, 3, 4]);
        assert_eq!(reader.u32(0).unwrap(), 0x04030201);
        assert!(reader.range(4, 0).unwrap().is_empty());
        for result in [
            reader.range(u64::MAX, 2),
            reader.array(0, u64::MAX, 2),
            reader.range(3, 2),
        ] {
            let error = result.unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidInput);
            assert!(error.details.contains_key("byte_offset"));
        }
    }
}
