use std::time::Instant;

use roaring::RoaringBitmap;

use crate::{
    backend::foundationdb::read::ReadTransaction,
    fts::{
        bloom::{BloomFilter, BloomHashGroup},
        builder::MAX_TOKEN_LENGTH,
        ngram::ToNgrams,
        stemmer::Stemmer,
        tokenizers::Tokenizer,
    },
    BitmapKey, ValueKey, BLOOM_BIGRAM, BLOOM_TRIGRAM, HASH_EXACT, HASH_STEMMED,
};

use super::Language;

impl ReadTransaction<'_> {
    pub(crate) async fn fts_query(
        &mut self,
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
                let key = BitmapKey::hash(
                    token.word.as_ref(),
                    account_id,
                    collection,
                    HASH_EXACT,
                    field,
                );
                if !bit_keys.contains(&key) {
                    bit_keys.push(key);
                }

                tokens.push(token.word);
            }
            let bitmaps = match self.get_bitmaps_intersection(bit_keys).await? {
                Some(b) if !b.is_empty() => b,
                _ => return Ok(None),
            };

            match tokens.len() {
                0 => return Ok(None),
                1 => return Ok(Some(bitmaps)),
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
            let mut bitmaps = RoaringBitmap::new();

            for token in Stemmer::new(text, language, MAX_TOKEN_LENGTH) {
                let token1 =
                    BitmapKey::hash(&token.word, account_id, collection, HASH_EXACT, field);
                let token2 = if let Some(stemmed_word) = token.stemmed_word {
                    BitmapKey::hash(&stemmed_word, account_id, collection, HASH_STEMMED, field)
                } else {
                    let mut token2 = token1.clone();
                    token2.family &= !HASH_EXACT;
                    token2.family |= HASH_STEMMED;
                    token2
                };

                self.refresh_if_old().await?;

                match self.get_bitmaps_union(vec![token1, token2]).await? {
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
            self.refresh_if_old().await?;

            if let Some(bloom) = self
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
