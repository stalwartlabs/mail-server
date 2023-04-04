pub mod error;
pub mod method;
pub mod object;
pub mod parser;
pub mod request;
pub mod types;

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    #[test]
    fn gen_hash() {
        //let mut table = BTreeMap::new();
        for value in ["blobIds", "ifInState", "emails"] {
            let mut hash = 0;
            let mut shift = 0;
            let lower_first = false;

            for (pos, &ch) in value.as_bytes().iter().take(16).enumerate() {
                if pos == 0 && lower_first {
                    hash |= (ch.to_ascii_lowercase() as u128) << shift;
                } else {
                    hash |= (ch as u128) << shift;
                }
                shift += 8;
            }

            shift = 0;
            let mut hash2 = 0;
            for &ch in value.as_bytes().iter().skip(16).take(16) {
                hash2 |= (ch as u128) << shift;
                shift += 8;
            }

            println!(
                "0x{} => {{}} // {}",
                format!("{hash:x}")
                    .as_bytes()
                    .chunks(4)
                    .into_iter()
                    .map(|s| std::str::from_utf8(s).unwrap())
                    .collect::<Vec<_>>()
                    .join("_"),
                value
            );
            /*println!(
                "(0x{}, 0x{}) => Filter::{}(),",
                format!("{hash:x}")
                    .as_bytes()
                    .chunks(4)
                    .into_iter()
                    .map(|s| std::str::from_utf8(s).unwrap())
                    .collect::<Vec<_>>()
                    .join("_"),
                format!("{hash2:x}")
                    .as_bytes()
                    .chunks(4)
                    .into_iter()
                    .map(|s| std::str::from_utf8(s).unwrap())
                    .collect::<Vec<_>>()
                    .join("_"),
                value
            );*/

            /*let mut hash = 0;
            let mut shift = 0;
            let mut first_ch = 0;
            let mut name = Vec::new();

            for (pos, &ch) in value.as_bytes().iter().take(16).enumerate() {
                if pos == 0 {
                    first_ch = ch.to_ascii_lowercase();
                    name.push(ch.to_ascii_uppercase());
                } else {
                    hash |= (ch as u128) << shift;
                    shift += 8;
                    name.push(ch);
                }
            }

            //println!("Property::{} => {{}}", std::str::from_utf8(&name).unwrap());

            table
                .entry(first_ch)
                .or_insert_with(|| vec![])
                .push((hash, name));*/
        }

        /*for (k, v) in table {
            println!("b'{}' => match hash {{", k as char);
            for (hash, value) in v {
                println!(
                    "    0x{} => Property::{},",
                    format!("{hash:x}")
                        .as_bytes()
                        .chunks(4)
                        .into_iter()
                        .map(|s| std::str::from_utf8(s).unwrap())
                        .collect::<Vec<_>>()
                        .join("_"),
                    std::str::from_utf8(&value).unwrap()
                );
            }
            println!("    _ => parser.invalid_property()?,");
            println!("}}");
        }*/
    }
}
