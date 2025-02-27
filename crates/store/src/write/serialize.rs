/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Deserialize, Serialize, SerializeInfallible, Value};

use super::{Archive, Archiver, LegacyBincode, assert::HashedValue};

const MAGIC_MARKER: u8 = 1 << 7;
const LZ4_COMPRESSES: u8 = 1 << 6;
const ARCHIVE_UNCOMPRESSED: u8 = MAGIC_MARKER;
const ARCHIVE_LZ4_COMPRESSED: u8 = MAGIC_MARKER | LZ4_COMPRESSES;
const COMPRESS_WATERMARK: usize = 8192;
const COMPRESS_DATA_OFFSET: usize = std::mem::size_of::<u32>() + 1;

impl Deserialize for Archive {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        match bytes.first().copied() {
            Some(ARCHIVE_UNCOMPRESSED) => Ok(Archive::Raw(bytes.to_vec())),
            Some(ARCHIVE_LZ4_COMPRESSED) => {
                lz4_flex::decompress_size_prepended(bytes.get(1..).unwrap_or_default())
                    .map_err(|err| {
                        trc::StoreEvent::DecompressError
                            .ctx(trc::Key::Value, bytes)
                            .caused_by(trc::location!())
                            .reason(err)
                    })
                    .map(Archive::Uncompressed)
            }
            _ => Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid archive marker.")
                .ctx(trc::Key::Value, bytes)
                .caused_by(trc::location!())),
        }
    }

    fn deserialize_owned(bytes: Vec<u8>) -> trc::Result<Self> {
        match bytes.first().copied() {
            Some(ARCHIVE_UNCOMPRESSED) => Ok(Archive::Raw(bytes)),
            Some(ARCHIVE_LZ4_COMPRESSED) => {
                lz4_flex::decompress_size_prepended(bytes.get(1..).unwrap_or_default())
                    .map_err(|err| {
                        trc::StoreEvent::DecompressError
                            .ctx(trc::Key::Value, bytes)
                            .caused_by(trc::location!())
                            .reason(err)
                    })
                    .map(Archive::Uncompressed)
            }
            _ => Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid archive marker.")
                .ctx(trc::Key::Value, bytes)
                .caused_by(trc::location!())),
        }
    }
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
                    let mut bytes = vec![
                        ARCHIVE_LZ4_COMPRESSED;
                        lz4_flex::block::get_maximum_output_size(input_len)
                            + COMPRESS_DATA_OFFSET
                    ];
                    bytes[1..COMPRESS_DATA_OFFSET]
                        .copy_from_slice(&(input_len as u32).to_le_bytes());
                    let bytes_len =
                        lz4_flex::compress_into(input, &mut bytes[COMPRESS_DATA_OFFSET..]).unwrap()
                            + COMPRESS_DATA_OFFSET;
                    if bytes_len < input_len {
                        bytes.truncate(bytes_len);
                    } else {
                        bytes.clear();
                        bytes.push(ARCHIVE_UNCOMPRESSED);
                        bytes.extend_from_slice(input);
                    }
                    bytes
                } else {
                    let mut bytes = Vec::with_capacity(input_len + 1);
                    bytes.push(ARCHIVE_UNCOMPRESSED);
                    bytes.extend_from_slice(input);
                    bytes
                }
            })
    }
}

impl Archive {
    pub fn unarchive<T>(&self) -> trc::Result<&T>
    where
        T: rkyv::Portable
            + for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + Sync
            + Send,
    {
        match self {
            Archive::Raw(bytes) => rkyv::access::<T, rkyv::rancor::Error>(bytes.get(1..).unwrap())
                .map_err(|err| {
                    trc::StoreEvent::DataCorruption
                        .caused_by(trc::location!())
                        .ctx(trc::Key::Value, bytes.as_slice())
                        .reason(err)
                }),
            Archive::Uncompressed(bytes) => Ok(unsafe { rkyv::access_unchecked::<T>(bytes) }),
        }
    }

    pub fn deserialize<T, V>(&self) -> trc::Result<V>
    where
        T: rkyv::Portable
            + for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + Sync
            + Send
            + rkyv::Deserialize<V, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.unarchive::<T>().and_then(|value| {
            rkyv::deserialize::<V, rkyv::rancor::Error>(value).map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .ctx(
                        trc::Key::Value,
                        match self {
                            Archive::Raw(bytes) => bytes,
                            Archive::Uncompressed(bytes) => bytes,
                        }
                        .as_slice(),
                    )
                    .caused_by(trc::location!())
                    .reason(err)
            })
        })
    }

    pub fn into_inner(self) -> Vec<u8> {
        match self {
            Archive::Raw(bytes) => bytes,
            Archive::Uncompressed(bytes) => {
                let mut result = Vec::with_capacity(bytes.len() + 1);
                result.push(ARCHIVE_UNCOMPRESSED);
                result.extend_from_slice(&bytes);
                result
            }
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
        Self(inner)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl HashedValue<Archive> {
    pub fn to_unarchived<T>(&self) -> trc::Result<HashedValue<&T>>
    where
        T: rkyv::Portable
            + for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + Sync
            + Send,
    {
        self.inner.unarchive().map(|inner| HashedValue {
            hash: self.hash,
            inner,
        })
    }

    pub fn into_deserialized<T, V>(self) -> trc::Result<HashedValue<V>>
    where
        T: rkyv::Portable
            + for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + Sync
            + Send
            + rkyv::Deserialize<V, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.inner.deserialize::<T, V>().map(|inner| HashedValue {
            hash: self.hash,
            inner,
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

pub fn rkyv_unarchive<T>(input: &[u8]) -> trc::Result<&T>
where
    T: rkyv::Portable
        + for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + Sync
        + Send,
{
    rkyv::access::<T, rkyv::rancor::Error>(input).map_err(|err| {
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

impl From<Value<'static>> for Archive {
    fn from(_: Value<'static>) -> Self {
        unimplemented!()
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> From<Value<'static>> for LegacyBincode<T> {
    fn from(_: Value<'static>) -> Self {
        unimplemented!()
    }
}
