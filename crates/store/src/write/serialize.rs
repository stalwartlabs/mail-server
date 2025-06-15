/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ARCHIVE_ALIGNMENT, AlignedBytes, Archive, ArchiveVersion, Archiver};
use crate::{Deserialize, Serialize, SerializeInfallible, U32_LEN, U64_LEN, Value};
use compact_str::format_compact;
use rkyv::util::AlignedVec;

const MAGIC_MARKER: u8 = 1 << 7;
const VERSIONED: u8 = 1 << 6;
const HASHED: u8 = 1 << 5;
const LZ4_COMPRESSED: u8 = 1 << 4;

const COMPRESS_WATERMARK: usize = 8192;

fn validate_marker_and_contents(bytes: &[u8]) -> Option<(bool, &[u8], ArchiveVersion)> {
    let (marker, contents) = bytes
        .split_last()
        .filter(|(marker, _)| (**marker & MAGIC_MARKER) != 0)?;
    let is_uncompressed = (marker & LZ4_COMPRESSED) == 0;
    if marker & VERSIONED != 0 {
        let (contents, change_id) = contents
            .split_at_checked(contents.len() - U64_LEN)
            .and_then(|(contents, change_id)| {
                change_id
                    .try_into()
                    .ok()
                    .map(|change_id| (contents, u64::from_be_bytes(change_id)))
            })?;
        contents
            .split_at_checked(contents.len() - U32_LEN)
            .and_then(|(contents, archive_hash)| {
                let hash = xxhash_rust::xxh3::xxh3_64(contents) as u32;
                if hash.to_be_bytes().as_slice() == archive_hash {
                    Some((
                        is_uncompressed,
                        contents,
                        ArchiveVersion::Versioned { change_id, hash },
                    ))
                } else {
                    None
                }
            })
    } else if marker & HASHED != 0 {
        contents
            .split_at_checked(contents.len() - U32_LEN)
            .and_then(|(contents, archive_hash)| {
                let hash = xxhash_rust::xxh3::xxh3_64(contents) as u32;
                if hash.to_be_bytes().as_slice() == archive_hash {
                    Some((is_uncompressed, contents, ArchiveVersion::Hashed { hash }))
                } else {
                    None
                }
            })
    } else {
        Some((is_uncompressed, contents, ArchiveVersion::Unversioned))
    }
}

impl Deserialize for Archive<AlignedBytes> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let (is_uncompressed, contents, version) =
            validate_marker_and_contents(bytes).ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Archive integrity compromised")
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
            })?;

        if is_uncompressed {
            let mut bytes = AlignedVec::with_capacity(contents.len());
            bytes.extend_from_slice(contents);
            Ok(Archive {
                version,
                inner: AlignedBytes::Aligned(bytes),
            })
        } else {
            aligned_lz4_deflate(contents).map(|inner| Archive { version, inner })
        }
    }

    fn deserialize_owned(mut bytes: Vec<u8>) -> trc::Result<Self> {
        let (is_uncompressed, contents, version) = validate_marker_and_contents(&bytes)
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Archive integrity compromised")
                    .ctx(trc::Key::Value, bytes.as_slice())
                    .caused_by(trc::location!())
            })?;

        if is_uncompressed {
            bytes.truncate(contents.len());
            if bytes.as_ptr().addr() & (ARCHIVE_ALIGNMENT - 1) == 0 {
                Ok(Archive {
                    version,
                    inner: AlignedBytes::Vec(bytes),
                })
            } else {
                let mut aligned = AlignedVec::with_capacity(bytes.len());
                aligned.extend_from_slice(&bytes);
                Ok(Archive {
                    version,
                    inner: AlignedBytes::Aligned(aligned),
                })
            }
        } else {
            aligned_lz4_deflate(contents).map(|inner| Archive { version, inner })
        }
    }
}

#[inline]
fn aligned_lz4_deflate(archive: &[u8]) -> trc::Result<AlignedBytes> {
    lz4_flex::block::uncompressed_size(archive)
        .and_then(|(uncompressed_size, archive)| {
            let mut bytes = AlignedVec::with_capacity(uncompressed_size);
            unsafe {
                // SAFETY: `new_len` is equal to `capacity` and vector is initialized by lz4_flex.
                bytes.set_len(uncompressed_size);
            }
            lz4_flex::decompress_into(archive, &mut bytes)?;
            Ok(AlignedBytes::Aligned(bytes))
        })
        .map_err(|err| {
            trc::StoreEvent::DecompressError
                .ctx(trc::Key::Value, archive)
                .caused_by(trc::location!())
                .reason(err)
        })
}

impl<T> Serialize for Archiver<T>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        rkyv::to_bytes::<rkyv::rancor::Error>(&self.inner)
            .map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .map(|input| {
                let input = input.as_ref();
                let input_len = input.len();
                let version_offset = ((self.flags & VERSIONED != 0) as usize) * U64_LEN;
                let mut bytes = if input_len > COMPRESS_WATERMARK {
                    let mut bytes = vec![
                        self.flags | LZ4_COMPRESSED;
                        lz4_flex::block::get_maximum_output_size(input_len)
                            + (U32_LEN * 2)
                            + version_offset
                            + 1
                    ];

                    // Compress the data
                    let compressed_len =
                        lz4_flex::compress_into(input, &mut bytes[U32_LEN..]).unwrap();

                    if compressed_len < input_len {
                        // Prepend the length of the uncompressed data
                        bytes[..U32_LEN].copy_from_slice(&(input_len as u32).to_le_bytes());

                        if self.flags & HASHED != 0 {
                            // Hash the compressed data including the length
                            let hash =
                                xxhash_rust::xxh3::xxh3_64(&bytes[..compressed_len + U32_LEN])
                                    as u32;

                            // Add the hash
                            bytes[compressed_len + U32_LEN..compressed_len + (U32_LEN * 2)]
                                .copy_from_slice(&hash.to_be_bytes());

                            // Truncate to the actual size
                            bytes.truncate(compressed_len + (U32_LEN * 2) + version_offset + 1);
                        } else {
                            // Truncate to the actual size
                            bytes.truncate(compressed_len + U32_LEN + 1);
                        }

                        return bytes;
                    }
                    bytes.clear();
                    bytes
                } else {
                    Vec::with_capacity(input_len + U32_LEN + version_offset + 1)
                };

                bytes.extend_from_slice(input);
                if self.flags & HASHED != 0 {
                    bytes.extend_from_slice(
                        &(xxhash_rust::xxh3::xxh3_64(input) as u32).to_be_bytes(),
                    );
                }
                if version_offset != 0 {
                    bytes.extend_from_slice(0u64.to_be_bytes().as_slice());
                }
                bytes.push(self.flags);
                bytes
            })
    }
}

impl Archive<AlignedBytes> {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match &self.inner {
            AlignedBytes::Vec(bytes) => bytes.as_slice(),
            AlignedBytes::Aligned(bytes) => bytes.as_slice(),
        }
    }

    pub fn unarchive<T>(&self) -> trc::Result<&<T as rkyv::Archive>::Archived>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        let bytes = self.as_bytes();
        if self.version != ArchiveVersion::Unversioned {
            if bytes.len() >= std::mem::size_of::<T::Archived>() {
                // SAFETY: Trusted input with integrity hash
                Ok(unsafe { rkyv::access_unchecked::<T::Archived>(bytes) })
            } else {
                Err(trc::StoreEvent::DataCorruption
                    .into_err()
                    .details(format_compact!(
                        "Archive size mismatch, expected {} bytes but got {} bytes.",
                        std::mem::size_of::<T::Archived>(),
                        bytes.len()
                    ))
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!()))
            }
        } else {
            rkyv::access::<T::Archived, rkyv::rancor::Error>(bytes).map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .ctx(trc::Key::Value, self.as_bytes())
                    .details("Archive access failed")
                    .caused_by(trc::location!())
                    .reason(err)
            })
        }
    }

    pub fn unarchive_untrusted<T>(&self) -> trc::Result<&<T as rkyv::Archive>::Archived>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        let bytes = self.as_bytes();
        if bytes.len() >= std::mem::size_of::<T::Archived>() {
            rkyv::access::<T::Archived, rkyv::rancor::Error>(bytes).map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .ctx(trc::Key::Value, self.as_bytes())
                    .details("Archive access failed")
                    .caused_by(trc::location!())
                    .reason(err)
            })
        } else {
            Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details(format_compact!(
                    "Archive size mismatch, expected {} bytes but got {} bytes.",
                    std::mem::size_of::<T::Archived>(),
                    bytes.len()
                ))
                .ctx(trc::Key::Value, bytes)
                .caused_by(trc::location!()))
        }
    }

    pub fn deserialize<T>(&self) -> trc::Result<T>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.unarchive::<T>().and_then(|input| {
            rkyv::deserialize(input).map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .ctx(trc::Key::Value, self.as_bytes())
                    .caused_by(trc::location!())
                    .reason(err)
            })
        })
    }

    pub fn to_unarchived<T>(&self) -> trc::Result<Archive<&<T as rkyv::Archive>::Archived>>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.unarchive::<T>().map(|inner| Archive {
            version: self.version,
            inner,
        })
    }

    pub fn into_deserialized<T>(&self) -> trc::Result<Archive<T>>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.deserialize::<T>().map(|inner| Archive {
            version: self.version,
            inner,
        })
    }

    pub fn into_inner(self) -> Vec<u8> {
        let mut bytes = match self.inner {
            AlignedBytes::Vec(bytes) => bytes,
            AlignedBytes::Aligned(bytes) => bytes.to_vec(),
        };
        match self.version {
            ArchiveVersion::Versioned { change_id, hash } => {
                bytes.extend_from_slice(&change_id.to_be_bytes());
                bytes.extend_from_slice(&hash.to_be_bytes());
                bytes.push(MAGIC_MARKER | VERSIONED | HASHED);
            }
            ArchiveVersion::Hashed { hash } => {
                bytes.extend_from_slice(&hash.to_be_bytes());
                bytes.push(MAGIC_MARKER | HASHED);
            }
            ArchiveVersion::Unversioned => {
                bytes.push(MAGIC_MARKER);
            }
        }
        bytes
    }

    pub fn extract_hash(bytes: &[u8]) -> Option<u32> {
        let marker = *bytes.last()?;
        if marker & VERSIONED != 0 {
            bytes
                .get(bytes.len() - U32_LEN - U64_LEN - 1..bytes.len() - U64_LEN - 1)
                .and_then(|slice| slice.try_into().ok().map(u32::from_be_bytes))
        } else if marker & HASHED != 0 {
            bytes
                .get(bytes.len() - U32_LEN - 1..bytes.len() - 1)
                .and_then(|slice| slice.try_into().ok().map(u32::from_be_bytes))
        } else {
            None
        }
    }
}

impl<T> Archiver<T>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            flags: MAGIC_MARKER | HASHED,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn with_version(self) -> Self {
        Self {
            inner: self.inner,
            flags: self.flags | VERSIONED,
        }
    }

    pub fn untrusted(self) -> Self {
        Self {
            inner: self.inner,
            flags: MAGIC_MARKER,
        }
    }

    pub fn serialize_versioned(self) -> trc::Result<(usize, Vec<u8>)> {
        self.with_version()
            .serialize()
            .map(|bytes| (bytes.len() - U64_LEN - 1, bytes))
    }
}

impl<T> Archive<&T>
where
    T: rkyv::Portable
        + for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + Sync
        + Send,
{
    pub fn to_deserialized<V>(&self) -> trc::Result<Archive<V>>
    where
        T: rkyv::Deserialize<V, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        rkyv::deserialize::<V, rkyv::rancor::Error>(self.inner)
            .map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .map(|inner| Archive {
                version: self.version,
                inner,
            })
    }

    pub fn deserialize<V>(&self) -> trc::Result<V>
    where
        T: rkyv::Deserialize<V, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        rkyv::deserialize::<V, rkyv::rancor::Error>(self.inner).map_err(|err| {
            trc::StoreEvent::DeserializeError
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

#[inline]
pub fn rkyv_deserialize<T, V>(input: &T) -> trc::Result<V>
where
    T: rkyv::Portable
        + for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + Sync
        + Send
        + rkyv::Deserialize<V, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    rkyv::deserialize::<V, rkyv::rancor::Error>(input).map_err(|err| {
        trc::StoreEvent::DeserializeError
            .caused_by(trc::location!())
            .reason(err)
    })
}

pub fn rkyv_unarchive<T>(input: &[u8]) -> trc::Result<&<T as rkyv::Archive>::Archived>
where
    T: rkyv::Archive,
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    rkyv::access::<T::Archived, rkyv::rancor::Error>(input).map_err(|err| {
        trc::StoreEvent::DataCorruption
            .caused_by(trc::location!())
            .ctx(trc::Key::Value, input)
            .reason(err)
    })
}

impl SerializeInfallible for u32 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for u64 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for i64 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for u16 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for f64 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for &str {
    fn serialize(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Deserialize for String {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    fn deserialize_owned(bytes: Vec<u8>) -> trc::Result<Self> {
        Ok(String::from_utf8(bytes)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()))
    }
}

impl Deserialize for u64 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
        })?))
    }
}

impl Deserialize for i64 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(i64::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
        })?))
    }
}

impl Deserialize for u32 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
        })?))
    }
}

impl Deserialize for () {
    fn deserialize(_bytes: &[u8]) -> trc::Result<Self> {
        Ok(())
    }
}

impl<T> From<Value<'static>> for Archive<T> {
    fn from(_: Value<'static>) -> Self {
        unimplemented!()
    }
}
