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
    pub uses_zip64: bool,
}

pub(super) fn invalid(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidInput, "archive.directory", message)
}

pub(super) fn checked(bytes: &[u8], offset: usize, len: usize) -> MddResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| invalid("ZIP range overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("ZIP range exceeds captured source"))
}

pub(super) fn u16_at(bytes: &[u8], offset: usize) -> MddResult<u16> {
    let value = checked(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

pub(super) fn u32_at(bytes: &[u8], offset: usize) -> MddResult<u32> {
    let value = checked(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub(super) fn descriptor_end(
    bytes: &[u8],
    start: usize,
    bound: usize,
    crc: u32,
    compressed: u64,
    size: u64,
    wide: bool,
) -> MddResult<usize> {
    let width = if wide { 20 } else { 12 };
    let mut candidates = Vec::new();
    for signature in [false, true] {
        let skip = if signature { 4 } else { 0 };
        let Some(end) = start.checked_add(skip + width) else {
            continue;
        };
        if end > bound {
            continue;
        }
        if signature && checked(bytes, start, 4)? != b"PK\x07\x08" {
            continue;
        }
        let at = start + skip;
        let (actual_compressed, actual_size) = if wide {
            (
                super::zip64::u64_at(bytes, at + 4)?,
                super::zip64::u64_at(bytes, at + 12)?,
            )
        } else {
            (
                u64::from(u32_at(bytes, at + 4)?),
                u64::from(u32_at(bytes, at + 8)?),
            )
        };
        if u32_at(bytes, at)? == crc && actual_compressed == compressed && actual_size == size {
            candidates.push(end);
        }
    }
    match candidates.as_slice() {
        [end] => Ok(*end),
        [] => Err(invalid("data descriptor disagrees with central member")),
        _ => Err(invalid(
            "data descriptor signature interpretation is ambiguous",
        )),
    }
}

pub(super) fn scan(bytes: &[u8], limits: &super::ArchiveLimits) -> MddResult<(Vec<Entry>, usize)> {
    if bytes.len() < 22 {
        return Err(invalid("truncated ZIP end record"));
    }
    let first = bytes.len().saturating_sub(22 + u16::MAX as usize);
    let end = (first..=bytes.len() - 22)
        .rev()
        .find(|&offset| {
            bytes.get(offset..offset + 4) == Some(b"PK\x05\x06")
                && u16_at(bytes, offset + 20)
                    .is_ok_and(|n| offset + 22 + usize::from(n) == bytes.len())
        })
        .ok_or_else(|| invalid("ZIP end record missing or comment length invalid"))?;
    let directory =
        super::zip64::directory(bytes, end, limits.max_members, limits.max_directory_bytes)?;
    let central_start = super::zip64::host(directory.start)?;
    let central_end = central_start
        .checked_add(super::zip64::host(directory.size)?)
        .ok_or_else(|| invalid("central directory length overflow"))?;
    let count = super::zip64::host(directory.count)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|e| MddError::new(ErrorCode::QuotaExceeded, "archive.directory", e.to_string()))?;
    let mut pos = central_start;
    let mut total = 0u64;
    for ordinal in 0..count {
        let fixed = checked(bytes, pos, 46)?;
        if &fixed[..4] != b"PK\x01\x02" {
            return Err(invalid("invalid central member header")
                .detail("member_ordinal", ordinal.to_string()));
        }
        let name_len = usize::from(u16_at(bytes, pos + 28)?);
        let extra_len = usize::from(u16_at(bytes, pos + 30)?);
        let comment_len = usize::from(u16_at(bytes, pos + 32)?);
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
        let flags = u16_at(bytes, pos + 8)?;
        let method = u16_at(bytes, pos + 10)?;
        let crc32 = u32_at(bytes, pos + 16)?;
        if flags & (1 | 0x40 | 0x2000) != 0 {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.directory",
                "encrypted ZIP members are not qualified",
            ));
        }
        let extra = checked(bytes, pos + 46 + name_len, extra_len)?;
        let resolved = super::zip64::central_sizes(
            extra,
            u32_at(bytes, pos + 24)?,
            u32_at(bytes, pos + 20)?,
            u32_at(bytes, pos + 42)?,
            u16_at(bytes, pos + 34)?,
        )?;
        if resolved.disk != 0 {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.directory",
                "multi-volume ZIP member is not qualified",
            ));
        }
        total = total.checked_add(resolved.size).ok_or_else(|| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "archive.budget",
                "uncompressed byte sum overflow",
            )
        })?;
        if resolved.size > limits.max_member_bytes || total > limits.max_total_uncompressed_bytes {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "archive.budget",
                "declared uncompressed bytes exceed budget",
            )
            .detail("member_ordinal", ordinal.to_string())
            .detail("member_bytes", resolved.size.to_string())
            .detail("total_bytes", total.to_string()));
        }
        let raw_name = checked(bytes, pos + 46, name_len)?.to_vec();
        let local = super::zip64::host(resolved.offset)?;
        let local_fixed = checked(bytes, local, 30)?;
        if &local_fixed[..4] != b"PK\x03\x04" {
            return Err(invalid("invalid local member header"));
        }
        let local_name_len = usize::from(u16_at(bytes, local + 26)?);
        let local_extra_len = usize::from(u16_at(bytes, local + 28)?);
        if u16_at(bytes, local + 6)? != flags
            || u16_at(bytes, local + 8)? != method
            || checked(bytes, local + 30, local_name_len)? != raw_name
        {
            return Err(invalid("local and central member identities disagree"));
        }
        let local_extra_start = local
            .checked_add(30)
            .and_then(|n| n.checked_add(local_name_len))
            .ok_or_else(|| invalid("local extra offset overflow"))?;
        let (local_size, local_compressed, local_zip64) = super::zip64::local_sizes(
            checked(bytes, local_extra_start, local_extra_len)?,
            u32_at(bytes, local + 22)?,
            u32_at(bytes, local + 18)?,
        )?;
        let uses_zip64 = resolved.zip64 || local_zip64;
        if (local_zip64 && u16_at(bytes, local + 4)? < 45)
            || (uses_zip64 && u16_at(bytes, pos + 6)? < 45)
        {
            return Err(invalid("ZIP64 member requires version 4.5 or later"));
        }
        let local_crc = u32_at(bytes, local + 14)?;
        if flags & 8 == 0 {
            if local_crc != crc32
                || local_size != resolved.size
                || local_compressed != resolved.compressed
            {
                return Err(invalid("local and central sizes or CRC disagree"));
            }
        } else if (local_crc != 0 && local_crc != crc32)
            || (local_size != 0 && local_size != resolved.size)
            || (local_compressed != 0 && local_compressed != resolved.compressed)
        {
            return Err(invalid(
                "descriptor local placeholders disagree with central member",
            ));
        }
        if method == 0 && resolved.size != resolved.compressed {
            return Err(invalid(
                "stored member compressed and original sizes disagree",
            ));
        }
        let data_start = local_extra_start
            .checked_add(local_extra_len)
            .ok_or_else(|| invalid("local data offset overflow"))?;
        let data_end64 = (data_start as u64)
            .checked_add(resolved.compressed)
            .ok_or_else(|| invalid("member compressed range overflow"))?;
        let data_end = super::zip64::host(data_end64)?;
        if data_end > central_start || local >= central_start {
            return Err(invalid("member data overlaps central directory"));
        }
        checked(bytes, data_start, super::zip64::host(resolved.compressed)?)?;
        let physical_end = if flags & 8 != 0 {
            descriptor_end(
                bytes,
                data_end,
                central_start,
                crc32,
                resolved.compressed,
                resolved.size,
                uses_zip64,
            )?
        } else {
            data_end
        };
        entries.push(Entry {
            ordinal,
            raw_name,
            flags,
            method,
            crc32,
            compressed_size: resolved.compressed,
            size: resolved.size,
            data_start,
            local_start: local,
            physical_end,
            central_start: pos,
            central_end: record_end,
            uses_zip64,
        });
        pos = record_end;
    }
    if pos != central_end
        && (checked(bytes, pos, 4)? != b"PK\x05\x05"
            || pos.checked_add(6 + usize::from(u16_at(bytes, pos + 4)?)) != Some(central_end))
    {
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
    end: Vec<u8>,
    position: u64,
}

impl<'a> MemberView<'a> {
    pub fn new(source: &'a [u8], directory_start: usize, entry: &Entry) -> MddResult<Self> {
        let central = checked(
            source,
            entry.central_start,
            entry.central_end - entry.central_start,
        )?;
        let end = super::zip64::tail(
            directory_start as u64,
            central.len() as u64,
            entry.uses_zip64,
        )?;
        Ok(Self {
            prefix: checked(source, 0, directory_start)?,
            central,
            end,
            position: 0,
        })
    }
    fn len(&self) -> u64 {
        (self.prefix.len() + self.central.len() + self.end.len()) as u64
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
