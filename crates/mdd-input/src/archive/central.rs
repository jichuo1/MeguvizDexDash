use mdd_types::{ErrorCode, MddError, MddResult};
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Clone)]
pub(super) struct Entry {
    pub ordinal: usize,
    pub raw_name: Vec<u8>,
    pub flags: u16,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    pub data_start: usize,
    local_start: usize,
    physical_end: usize,
    pub central_start: usize,
    pub central_end: usize,
}

fn invalid(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidInput, "archive.directory", message)
}

fn checked(bytes: &[u8], offset: usize, len: usize) -> MddResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| invalid("ZIP range overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("ZIP range exceeds captured source"))
}

fn u16_at(bytes: &[u8], offset: usize) -> MddResult<u16> {
    let value = checked(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> MddResult<u32> {
    let value = checked(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub(super) fn scan(
    bytes: &[u8],
    max_members: usize,
    max_directory_bytes: u64,
) -> MddResult<(Vec<Entry>, usize)> {
    if bytes.len() < 22 {
        return Err(invalid("truncated ZIP end record"));
    }
    let first = bytes.len().saturating_sub(22 + u16::MAX as usize);
    let end = (first..=bytes.len() - 22)
        .rev()
        .find(|&offset| {
            bytes.get(offset..offset + 4) == Some(b"PK\x05\x06")
                && u16_at(bytes, offset + 20).is_ok_and(|n| offset + 22 + n as usize == bytes.len())
        })
        .ok_or_else(|| invalid("ZIP end record missing or comment length invalid"))?;
    let disk = u16_at(bytes, end + 4)?;
    let directory_disk = u16_at(bytes, end + 6)?;
    let disk_count = u16_at(bytes, end + 8)?;
    let count = u16_at(bytes, end + 10)?;
    let central_size = u32_at(bytes, end + 12)?;
    let central_start = u32_at(bytes, end + 16)?;
    if count == u16::MAX || central_size == u32::MAX || central_start == u32::MAX {
        return Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "archive.directory",
            "ZIP64 is not qualified",
        ));
    }
    if disk == 0 && directory_disk == 0 && disk_count != count {
        return Err(invalid("single-volume member counts disagree"));
    }
    if disk != 0 || directory_disk != 0 {
        return Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "archive.directory",
            "multi-volume ZIP is not qualified",
        ));
    }
    if count as usize > max_members {
        return Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "archive.directory",
            "member count exceeds budget",
        )
        .detail("limit", max_members.to_string())
        .detail("declared", count.to_string()));
    }
    if u64::from(central_size) > max_directory_bytes {
        return Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "archive.directory",
            "central directory bytes exceed metadata budget",
        )
        .detail("declared", central_size.to_string())
        .detail("limit", max_directory_bytes.to_string()));
    }
    let central_start = central_start as usize;
    let central_end = central_start
        .checked_add(central_size as usize)
        .ok_or_else(|| invalid("central directory length overflow"))?;
    if central_end != end {
        return Err(invalid("central directory does not end at the end record"));
    }
    checked(bytes, central_start, central_size as usize)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count as usize)
        .map_err(|e| MddError::new(ErrorCode::QuotaExceeded, "archive.directory", e.to_string()))?;
    let mut pos = central_start;
    for ordinal in 0..count as usize {
        let fixed = checked(bytes, pos, 46)?;
        if &fixed[..4] != b"PK\x01\x02" {
            return Err(invalid("invalid central member header")
                .detail("member_ordinal", ordinal.to_string()));
        }
        let name_len = u16_at(bytes, pos + 28)? as usize;
        let extra_len = u16_at(bytes, pos + 30)? as usize;
        let comment_len = u16_at(bytes, pos + 32)? as usize;
        let record_len = 46usize
            .checked_add(name_len)
            .and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comment_len))
            .ok_or_else(|| invalid("member header length overflow"))?;
        let record_end = pos
            .checked_add(record_len)
            .ok_or_else(|| invalid("member header offset overflow"))?;
        if record_end > central_end {
            return Err(invalid("member header crosses central directory"));
        }
        checked(bytes, pos, record_len)?;
        let compressed_size = u32_at(bytes, pos + 20)?;
        let size = u32_at(bytes, pos + 24)?;
        let local_start = u32_at(bytes, pos + 42)?;
        if compressed_size == u32::MAX
            || size == u32::MAX
            || local_start == u32::MAX
            || u16_at(bytes, pos + 34)? != 0
        {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.directory",
                "ZIP64 or multi-volume member is not qualified",
            ));
        }
        let raw_name = checked(bytes, pos + 46, name_len)?.to_vec();
        let local = local_start as usize;
        let local_fixed = checked(bytes, local, 30)?;
        if &local_fixed[..4] != b"PK\x03\x04" {
            return Err(invalid("invalid local member header"));
        }
        let flags = u16_at(bytes, pos + 8)?;
        let method = u16_at(bytes, pos + 10)?;
        let crc32 = u32_at(bytes, pos + 16)?;
        let local_name_len = u16_at(bytes, local + 26)? as usize;
        let local_extra_len = u16_at(bytes, local + 28)? as usize;
        if u16_at(bytes, local + 6)? != flags
            || u16_at(bytes, local + 8)? != method
            || checked(bytes, local + 30, local_name_len)? != raw_name
        {
            return Err(invalid("local and central member identities disagree"));
        }
        if flags & 8 == 0
            && (u32_at(bytes, local + 14)? != crc32
                || u32_at(bytes, local + 18)? != compressed_size
                || u32_at(bytes, local + 22)? != size)
        {
            return Err(invalid("local and central sizes or CRC disagree"));
        }
        let data_start = local
            .checked_add(30)
            .and_then(|n| n.checked_add(local_name_len))
            .and_then(|n| n.checked_add(local_extra_len))
            .ok_or_else(|| invalid("local data offset overflow"))?;
        let data_end = data_start
            .checked_add(compressed_size as usize)
            .ok_or_else(|| invalid("member compressed range overflow"))?;
        if data_end > central_start || local >= central_start {
            return Err(invalid("member data overlaps central directory"));
        }
        checked(bytes, data_start, compressed_size as usize)?;
        let mut physical_end = data_end;
        if flags & 8 != 0 {
            let descriptor = if checked(bytes, data_end, 4)? == b"PK\x07\x08" {
                data_end
                    .checked_add(4)
                    .ok_or_else(|| invalid("data descriptor overflow"))?
            } else {
                data_end
            };
            let descriptor_end = descriptor
                .checked_add(12)
                .ok_or_else(|| invalid("data descriptor overflow"))?;
            if descriptor_end > central_start
                || u32_at(bytes, descriptor)? != crc32
                || u32_at(bytes, descriptor + 4)? != compressed_size
                || u32_at(bytes, descriptor + 8)? != size
            {
                return Err(invalid("data descriptor disagrees with central member"));
            }
            physical_end = descriptor_end;
        }
        entries.push(Entry {
            ordinal,
            raw_name,
            flags,
            method,
            crc32,
            compressed_size: compressed_size as u64,
            size: size as u64,
            data_start,
            local_start: local,
            physical_end,
            central_start: pos,
            central_end: record_end,
        });
        pos = record_end;
    }
    if pos != central_end {
        return Err(invalid("central directory count or byte length disagrees"));
    }
    let mut intervals: Vec<_> = entries
        .iter()
        .map(|e| (e.local_start, e.physical_end))
        .collect();
    intervals.sort_unstable();
    for pair in intervals.windows(2) {
        if pair[0].1 > pair[1].0 && pair[0] != pair[1] {
            return Err(invalid("physical member ranges partially overlap"));
        }
    }
    Ok((entries, central_start))
}

// zip 8.6 deduplicates names before by_index. Keep the original central ordinal,
// and expose one original central record at a time without copying compressed data.
pub(super) struct MemberView<'a> {
    prefix: &'a [u8],
    central: &'a [u8],
    end: [u8; 22],
    position: u64,
}

impl<'a> MemberView<'a> {
    pub fn new(source: &'a [u8], directory_start: usize, entry: &Entry) -> MddResult<Self> {
        let central = checked(
            source,
            entry.central_start,
            entry.central_end - entry.central_start,
        )?;
        let mut end = [0u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8..10].copy_from_slice(&1u16.to_le_bytes());
        end[10..12].copy_from_slice(&1u16.to_le_bytes());
        end[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
        end[16..20].copy_from_slice(&(directory_start as u32).to_le_bytes());
        Ok(Self {
            prefix: checked(source, 0, directory_start)?,
            central,
            end,
            position: 0,
        })
    }
    fn len(&self) -> u64 {
        (self.prefix.len() + self.central.len() + 22) as u64
    }
}

impl Read for MemberView<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut count = 0;
        while count < buffer.len() && self.position < self.len() {
            let pos = self.position as usize;
            let part = if pos < self.prefix.len() {
                &self.prefix[pos..]
            } else if pos < self.prefix.len() + self.central.len() {
                &self.central[pos - self.prefix.len()..]
            } else {
                &self.end[pos - self.prefix.len() - self.central.len()..]
            };
            let n = part.len().min(buffer.len() - count);
            buffer[count..count + n].copy_from_slice(&part[..n]);
            count += n;
            self.position += n as u64;
        }
        Ok(count)
    }
}

impl Seek for MemberView<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.len() as i128 + n as i128,
            SeekFrom::Current(n) => self.position as i128 + n as i128,
        };
        self.position = u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid member view seek"))?;
        Ok(self.position)
    }
}
