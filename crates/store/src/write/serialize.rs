/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rkyv::util::AlignedVec;

use crate::{Deserialize, Serialize, SerializeInfallible, SerializedVersion, U32_LEN, Value};

use super::{ARCHIVE_ALIGNMENT, AlignedBytes, Archive, Archiver, LegacyBincode};

const MAGIC_MARKER: u8 = 1 << 7;
const LZ4_COMPRESSED: u8 = 1 << 6;
const ARCHIVE_UNCOMPRESSED: u8 = MAGIC_MARKER;
const ARCHIVE_LZ4_COMPRESSED: u8 = MAGIC_MARKER | LZ4_COMPRESSED;
const COMPRESS_WATERMARK: usize = 8192;
const HASH_SEED: i64 = 791120;

const MARKER_MASK: u8 = MAGIC_MARKER | LZ4_COMPRESSED;
const VERSION_MASK: u8 = !MARKER_MASK;

impl Deserialize for Archive<AlignedBytes> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let (contents, marker, hash) = bytes
            .split_at_checked(bytes.len() - (U32_LEN + 1))
            .and_then(|(contents, marker)| {
                marker.split_first().and_then(|(marker, archive_hash)| {
                    let hash = gxhash::gxhash32(contents, HASH_SEED);
                    if hash.to_be_bytes().as_slice() == archive_hash {
                        Some((contents, *marker, hash))
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Archive integrity compromised")
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
            })?;

        match marker & MARKER_MASK {
            ARCHIVE_UNCOMPRESSED => {
                let mut bytes = AlignedVec::with_capacity(contents.len());
                bytes.extend_from_slice(contents);
                Ok(Archive {
                    hash,
                    version: marker & VERSION_MASK,
                    inner: AlignedBytes::Aligned(bytes),
                })
            }
            ARCHIVE_LZ4_COMPRESSED => aligned_lz4_deflate(contents).map(|inner| Archive {
                hash,
                version: marker & VERSION_MASK,
                inner,
            }),
            _ => Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid archive marker.")
                .ctx(trc::Key::Value, bytes)
                .caused_by(trc::location!())),
        }
    }

    fn deserialize_owned(mut bytes: Vec<u8>) -> trc::Result<Self> {
        let (contents, marker, hash) = bytes
            .split_at_checked(bytes.len() - (U32_LEN + 1))
            .and_then(|(contents, marker)| {
                marker.split_first().and_then(|(marker, archive_hash)| {
                    let hash = gxhash::gxhash32(contents, HASH_SEED);
                    if hash.to_be_bytes().as_slice() == archive_hash {
                        Some((contents, *marker, hash))
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Archive integrity compromised")
                    .ctx(trc::Key::Value, bytes.as_slice())
                    .caused_by(trc::location!())
            })?;

        match marker & MARKER_MASK {
            ARCHIVE_UNCOMPRESSED => {
                bytes.truncate(contents.len());
                if bytes.as_ptr().addr() & (ARCHIVE_ALIGNMENT - 1) == 0 {
                    Ok(Archive {
                        hash,
                        version: marker & VERSION_MASK,
                        inner: AlignedBytes::Vec(bytes),
                    })
                } else {
                    let mut aligned = AlignedVec::with_capacity(bytes.len());
                    aligned.extend_from_slice(&bytes);
                    Ok(Archive {
                        hash,
                        version: marker & VERSION_MASK,
                        inner: AlignedBytes::Aligned(aligned),
                    })
                }
            }
            ARCHIVE_LZ4_COMPRESSED => aligned_lz4_deflate(contents).map(|inner| Archive {
                hash,
                version: marker & VERSION_MASK,
                inner,
            }),
            _ => Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid archive marker.")
                .ctx(trc::Key::Value, bytes)
                .caused_by(trc::location!())),
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
        + SerializedVersion
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        rkyv::to_bytes::<rkyv::rancor::Error>(&self.0)
            .map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .map(|input| {
                let input = input.as_ref();
                let input_len = input.len();
                if input_len > COMPRESS_WATERMARK {
                    let mut bytes =
                        vec![
                            ARCHIVE_LZ4_COMPRESSED | (T::serialize_version() & VERSION_MASK);
                            lz4_flex::block::get_maximum_output_size(input_len) + (U32_LEN * 2) + 1
                        ];
                    let compressed_len =
                        lz4_flex::compress_into(input, &mut bytes[U32_LEN..]).unwrap();
                    if compressed_len < input_len {
                        bytes[..U32_LEN].copy_from_slice(&(input_len as u32).to_le_bytes());
                        let hash = gxhash::gxhash32(&bytes[..compressed_len + U32_LEN], HASH_SEED);
                        bytes[compressed_len + U32_LEN + 1..compressed_len + (U32_LEN * 2) + 1]
                            .copy_from_slice(&hash.to_be_bytes());
                        bytes.truncate(compressed_len + (U32_LEN * 2) + 1);
                    } else {
                        bytes.clear();
                        bytes.extend_from_slice(input);
                        bytes.push(ARCHIVE_UNCOMPRESSED | (T::serialize_version() & VERSION_MASK));
                        bytes.extend_from_slice(&gxhash::gxhash32(input, HASH_SEED).to_be_bytes());
                    }
                    bytes
                } else {
                    let mut bytes = Vec::with_capacity(input_len + U32_LEN + 1);
                    bytes.extend_from_slice(input);
                    bytes.push(ARCHIVE_UNCOMPRESSED | (T::serialize_version() & VERSION_MASK));
                    bytes.extend_from_slice(&gxhash::gxhash32(input, HASH_SEED).to_be_bytes());
                    bytes
                }
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
        T: rkyv::Archive + SerializedVersion,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        if self.version == T::serialize_version() {
            // SAFETY: Trusted and versioned input with integrity hash
            Ok(unsafe { rkyv::access_unchecked::<T::Archived>(self.as_bytes()) })
        } else {
            Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details(format!(
                    "Archive version mismatch, expected {} but got {}",
                    T::serialize_version(),
                    self.version
                ))
                .ctx(trc::Key::Value, self.as_bytes())
                .caused_by(trc::location!()))
        }
    }

    pub fn deserialize<T>(&self) -> trc::Result<T>
    where
        T: rkyv::Archive + SerializedVersion,
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
        T: rkyv::Archive + SerializedVersion,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.unarchive::<T>().map(|inner| Archive {
            hash: self.hash,
            version: self.version,
            inner,
        })
    }

    pub fn into_deserialized<T>(&self) -> trc::Result<Archive<T>>
    where
        T: rkyv::Archive + SerializedVersion,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.deserialize::<T>().map(|inner| Archive {
            hash: self.hash,
            version: self.version,
            inner,
        })
    }

    pub fn into_inner(self) -> Vec<u8> {
        let mut bytes = match self.inner {
            AlignedBytes::Vec(bytes) => bytes,
            AlignedBytes::Aligned(bytes) => bytes.to_vec(),
        };
        bytes.push(ARCHIVE_UNCOMPRESSED);
        bytes.extend_from_slice(&self.hash.to_be_bytes());
        bytes
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
        Self(inner)
    }

    pub fn into_inner(self) -> T {
        self.0
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
                hash: self.hash,
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

impl<T: serde::Serialize + serde::de::DeserializeOwned> LegacyBincode<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> Serialize for LegacyBincode<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        bincode::serialize(&self.inner)
            .map(|bytes| lz4_flex::compress_prepend_size(&bytes))
            .map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .caused_by(trc::location!())
                    .reason(err)
            })
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned + Sized + Sync + Send> Deserialize
    for LegacyBincode<T>
{
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        lz4_flex::decompress_size_prepended(bytes)
            .map_err(|err| {
                trc::StoreEvent::DecompressError
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .and_then(|result| {
                bincode::deserialize(&result).map_err(|err| {
                    trc::StoreEvent::DataCorruption
                        .ctx(trc::Key::Value, bytes)
                        .caused_by(trc::location!())
                        .reason(err)
                })
            })
            .map(|inner| Self { inner })
    }
}

impl<T> From<Value<'static>> for Archive<T> {
    fn from(_: Value<'static>) -> Self {
        unimplemented!()
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> From<Value<'static>> for LegacyBincode<T> {
    fn from(_: Value<'static>) -> Self {
        unimplemented!()
    }
}
