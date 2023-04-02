pub mod assign_id;
pub mod query;

use std::{io::Read, sync::Arc};

use super::*;

#[tokio::test]
pub async fn store_test() {
    let db = Arc::new(Store::open().await.unwrap());
    let insert = false;
    if insert {
        db.destroy().await;
    }
    //assign_id::test(db).await;

    query::test(db, insert).await;
}

pub fn deflate_artwork_data() -> Vec<u8> {
    let mut csv_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    csv_path.push("src");
    csv_path.push("tests");
    csv_path.push("resources");
    csv_path.push("artwork_data.csv.gz");

    let mut decoder = flate2::bufread::GzDecoder::new(std::io::BufReader::new(
        std::fs::File::open(csv_path).unwrap(),
    ));
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).unwrap();
    result
}

/*
#[test]
fn it_works() {
    for n in [10, 100, 1000, 5000, 10000, 100000] {
        let mut rb1 = RoaringBitmap::new();
        let mut h = BTreeSet::new();
        let m = (((n as f64) * f64::ln(0.01) / (-8.0 * LN_2.powi(2))).ceil() as u64) * 8;

        for pos in 0..(n * 7_usize) {
            let num = rand::thread_rng().gen_range(0..m as u32);
            rb1.insert(num);
            h.insert(num);
        }

        let mut compressed = vec![0u8; 4 * BitPacker8x::BLOCK_LEN];
        let mut bitpacker = BitPacker8x::new();
        let mut initial_value = 0;
        let mut bytes = vec![];
        for chunk in h
            .into_iter()
            .collect::<Vec<_>>()
            .chunks_exact(BitPacker8x::BLOCK_LEN)
        {
            let num_bits: u8 = bitpacker.num_bits_sorted(initial_value, chunk);
            let compressed_len =
                bitpacker.compress_sorted(initial_value, chunk, &mut compressed[..], num_bits);
            initial_value = chunk[chunk.len() - 1];
            //println!("{:?} {}", compressed_len, num_bits);
            bytes.push(num_bits);
            bytes.extend_from_slice(&compressed[..compressed_len]);
        }

        let rb_size = rb1.serialized_size();
        let bp_size = bytes.len();
        if rb_size < bp_size {
            println!("For {} Roaring is better {} vs {}", n, rb_size, bp_size);
        } else {
            println!("For {} BitPack is better {} vs {}", n, bp_size, rb_size);
        }
        let now = Instant::now();
        let mut ser = Vec::with_capacity(rb_size);
        rb1.serialize_into(&mut ser).unwrap();
        println!("Roaring serialization took {:?}", now.elapsed().as_millis());
        let now = Instant::now();
        let deser = RoaringBitmap::deserialize_unchecked_from(&ser[..]).unwrap();
        println!(
            "Roaring deserialization took {:?}",
            now.elapsed().as_millis()
        );
    }
    /*println!(
        "ratio: {}",
        rb1.serialized_size() as f64 / rb2.serialized_size() as f64
    );*/
}
*/
