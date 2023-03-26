use std::time::Instant;

use roaring::RoaringBitmap;

use crate::{
    fts::{
        bloom::{BloomFilter, BloomHash, BloomHashGroup},
        builder::MAX_TOKEN_LENGTH,
        ngram::ToNgrams,
        stemmer::Stemmer,
        tokenizers::Tokenizer,
    },
    write::key::KeySerializer,
    BitmapKey, Store, ValueKey, BLOOM_BIGRAM, BLOOM_STEMMED, BLOOM_TRIGRAM, BM_BLOOM,
};

use super::{Language, HIGH_RANK_MOD};

impl Store {
    pub(crate) fn fts_query(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        text: &str,
        language: Language,
        match_phrase: bool,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let real_now = Instant::now();

        let (bitmaps, hashes, family) = if match_phrase {
            let mut tokens = Vec::new();
            let mut bit_keys = Vec::new();
            for token in Tokenizer::new(text, language, MAX_TOKEN_LENGTH) {
                let hash = BloomHash::from(token.word.as_ref());
                let key = hash.to_high_rank_key(account_id, collection, field, 0);
                if !bit_keys.contains(&key) {
                    bit_keys.push(key);
                }

                tokens.push(token.word);
            }
            let bitmaps = match self.get_bitmaps_intersection(bit_keys)? {
                Some(b) if !b.is_empty() => b,
                _ => return Ok(None),
            };

            match tokens.len() {
                0 => (bitmaps, vec![], BLOOM_STEMMED),
                1 => (
                    bitmaps,
                    vec![tokens.into_iter().next().unwrap().into()],
                    BLOOM_STEMMED,
                ),
                2 => (
                    bitmaps,
                    <Vec<BloomHashGroup>>::to_ngrams(&tokens, 2),
                    BLOOM_BIGRAM,
                ),
                _ => (
                    bitmaps,
                    <Vec<BloomHashGroup>>::to_ngrams(&tokens, 3),
                    BLOOM_TRIGRAM,
                ),
            }
        } else {
            let mut hashes = Vec::new();
            let mut bitmaps = RoaringBitmap::new();

            for token in Stemmer::new(text, language, MAX_TOKEN_LENGTH) {
                let hash = BloomHashGroup {
                    h2: if let Some(stemmed_word) = token.stemmed_word {
                        Some(format!("{stemmed_word}_").into())
                    } else {
                        Some(format!("{}_", token.word).into())
                    },
                    h1: token.word.into(),
                };

                match self.get_bitmaps_union(vec![
                    hash.h1.to_high_rank_key(account_id, collection, field, 0),
                    hash.h2
                        .as_ref()
                        .unwrap()
                        .to_high_rank_key(account_id, collection, field, 0),
                ])? {
                    Some(b) if !b.is_empty() => {
                        if !bitmaps.is_empty() {
                            bitmaps &= b;
                            if bitmaps.is_empty() {
                                return Ok(None);
                            }
                        } else {
                            bitmaps = b;
                        }
                    }
                    _ => return Ok(None),
                };

                hashes.push(hash);
            }

            (bitmaps, hashes, BLOOM_STEMMED)
        };

        let b_count = bitmaps.len();
        let mut bm = RoaringBitmap::new();

        /*let keys = bitmaps
            .iter()
            .map(|document_id| {
                KeySerializer::new(std::mem::size_of::<ValueKey>())
                    .write_leb128(account_id)
                    .write(collection)
                    .write_leb128(document_id)
                    .write(u8::MAX)
                    .write(BM_BLOOM | family)
                    .write(field)
                    .finalize()
            })
            .collect::<Vec<_>>();

        self.get_values::<BloomFilter>(keys)?
            .into_iter()
            .zip(bitmaps)
            .for_each(|(bloom, document_id)| {
                if let Some(bloom) = bloom {
                    if !bloom.is_empty() {
                        let mut matched = true;
                        for hash in &hashes {
                            if !(bloom.contains(&hash.h1)
                                || hash.h2.as_ref().map_or(false, |h2| bloom.contains(h2)))
                            {
                                matched = false;
                                break;
                            }
                        }

                        if matched {
                            bm.insert(document_id);
                        }
                    }
                }
            });*/
        for document_id in bitmaps {
            let key = KeySerializer::new(std::mem::size_of::<ValueKey>() + 2)
                .write_leb128(account_id)
                .write(collection)
                .write_leb128(document_id)
                .write(u8::MAX)
                .write(BM_BLOOM | family)
                .write(field)
                .finalize();

            if let Some(bloom) = self.get_value::<BloomFilter>(key)? {
                if !bloom.is_empty() {
                    let mut matched = true;
                    for hash in &hashes {
                        if !(bloom.contains(&hash.h1)
                            || hash.h2.as_ref().map_or(false, |h2| bloom.contains(h2)))
                        {
                            matched = false;
                            break;
                        }
                    }

                    if matched {
                        bm.insert(document_id);
                    }
                }
            }
        }

        println!(
            "bloom_match {b_count} items in {:?}ms",
            real_now.elapsed().as_millis()
        );

        Ok(Some(bm))
    }
}

impl BloomHash {
    #[inline(always)]
    pub fn as_high_rank_hash(&self, n: usize) -> u16 {
        (self.h[n] % HIGH_RANK_MOD) as u16
    }

    pub fn to_high_rank_key(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        n: usize,
    ) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<BitmapKey<&[u8]>>() + 2)
            .write_leb128(account_id)
            .write(collection)
            .write(BM_BLOOM)
            .write(field)
            .write(self.as_high_rank_hash(n))
            .finalize()
    }
}
