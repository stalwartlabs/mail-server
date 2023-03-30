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
    BitmapKey, Serialize, Store, ValueKey, BLOOM_BIGRAM, BLOOM_TRIGRAM, BLOOM_UNIGRAM, BM_BLOOM,
};

use super::{Language, HIGH_RANK_MOD};

impl Store {
    pub(crate) async fn fts_query(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        text: &str,
        language: Language,
        match_phrase: bool,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let real_now = Instant::now();
        let mut trx = self.read_transaction().await?;

        let (bitmaps, hashes, family) = if match_phrase {
            let mut tokens = Vec::new();
            let mut bit_keys = Vec::new();
            for token in Tokenizer::new(text, language, MAX_TOKEN_LENGTH) {
                let hash = BloomHash::from(token.word.as_ref());
                let key = hash.to_high_rank_key(account_id, collection, field);
                if !bit_keys.contains(&key) {
                    bit_keys.push(key);
                }

                tokens.push(token.word);
            }
            let bitmaps = match trx.get_bitmaps_intersection(bit_keys).await? {
                Some(b) if !b.is_empty() => b,
                _ => return Ok(None),
            };

            match tokens.len() {
                0 => return Ok(None),
                1 => (
                    bitmaps,
                    vec![tokens.into_iter().next().unwrap().into()],
                    BM_BLOOM | BLOOM_UNIGRAM,
                ),
                2 => (
                    bitmaps,
                    <Vec<BloomHashGroup>>::to_ngrams(&tokens, 2),
                    BM_BLOOM | BLOOM_BIGRAM,
                ),
                _ => (
                    bitmaps,
                    <Vec<BloomHashGroup>>::to_ngrams(&tokens, 3),
                    BM_BLOOM | BLOOM_TRIGRAM,
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
                trx.refresh_if_old().await?;

                match trx
                    .get_bitmaps_union(vec![
                        hash.h1.to_high_rank_key(account_id, collection, field),
                        hash.h2
                            .as_ref()
                            .unwrap()
                            .to_high_rank_key(account_id, collection, field),
                    ])
                    .await?
                {
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

            (bitmaps, hashes, BM_BLOOM | BLOOM_UNIGRAM)
        };

        let b_count = bitmaps.len();

        /*let bm = self
        .get_values::<BloomFilter>(
            bitmaps
                .iter()
                .map(|document_id| ValueKey {
                    account_id,
                    collection,
                    document_id,
                    family,
                    field,
                })
                .collect::<Vec<_>>(),
        )
        .await?
        .into_iter()
        .zip(bitmaps)
        .filter_map(|(bloom, document_id)| {
            let bloom = bloom?;
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
                    return Some(document_id);
                }
            }

            None
        })
        .collect::<RoaringBitmap>();*/

        let mut bm = RoaringBitmap::new();
        for document_id in bitmaps {
            trx.refresh_if_old().await?;

            if let Some(bloom) = trx
                .get_value::<BloomFilter>(ValueKey {
                    account_id,
                    collection,
                    document_id,
                    family,
                    field,
                })
                .await?
            {
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
            "bloom_match {text:?} {b_count} items in {:?}ms",
            real_now.elapsed().as_millis()
        );

        Ok(Some(bm))
    }
}

impl BloomHash {
    #[inline(always)]
    pub fn as_high_rank_hash(&self) -> u16 {
        (self.h[0] % HIGH_RANK_MOD) as u16
    }

    pub fn to_high_rank_key(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
    ) -> BitmapKey<Vec<u8>> {
        BitmapKey {
            account_id,
            collection,
            family: BM_BLOOM,
            field,
            block_num: 0,
            key: self.as_high_rank_hash().serialize(),
        }
    }
}
