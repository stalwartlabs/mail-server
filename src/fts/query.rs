use std::time::Instant;

use roaring::RoaringBitmap;

use crate::{
    fts::{
        bloom::{hash_token, BloomFilter, BloomHash, BloomHashGroup},
        builder::MAX_TOKEN_LENGTH,
        ngram::ToNgrams,
        stemmer::Stemmer,
        tokenizers::Tokenizer,
    },
    BitmapKey, Store, ValueKey, BLOOM_BIGRAM, BLOOM_TRIGRAM, BLOOM_UNIGRAM, BLOOM_UNIGRAM_STEM,
    BM_BLOOM,
};

use super::Language;

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
                let key = hash.to_bitmap_key(account_id, collection, field);
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
                1 => return Ok(Some(bitmaps)),
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
            let mut bitmaps = RoaringBitmap::new();

            for token in Stemmer::new(text, language, MAX_TOKEN_LENGTH) {
                let token1 = hash_token(&token.word);
                let token2 = if let Some(stemmed_word) = token.stemmed_word {
                    hash_token(&stemmed_word)
                } else {
                    token1.clone()
                };

                trx.refresh_if_old().await?;

                match trx
                    .get_bitmaps_union(vec![
                        BitmapKey {
                            account_id,
                            collection,
                            family: BM_BLOOM | BLOOM_UNIGRAM,
                            field,
                            block_num: 0,
                            key: token1,
                        },
                        BitmapKey {
                            account_id,
                            collection,
                            family: BM_BLOOM | BLOOM_UNIGRAM_STEM,
                            field,
                            block_num: 0,
                            key: token2,
                        },
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
            }

            return Ok(Some(bitmaps));
        };

        let b_count = bitmaps.len();

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
