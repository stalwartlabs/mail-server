/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{tokenizer::Tokenizer, DavParser, RawElement, Token},
    schema::request::{
        ArchivedDeadElementTag, ArchivedDeadProperty, ArchivedDeadPropertyTag, DeadElementTag,
        DeadProperty, DeadPropertyTag,
    },
};

pub mod acl;
pub mod lockinfo;
pub mod mkcol;
pub mod propertyupdate;
pub mod propfind;
pub mod report;

impl DavParser for DeadProperty {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut depth = 1;
        let mut items = DeadProperty::default();

        loop {
            match stream.token()? {
                Token::ElementStart { raw, .. } | Token::UnknownElement(raw) => {
                    items.0.push(DeadPropertyTag::ElementStart((&raw).into()));
                    depth += 1;
                }
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    items.0.push(DeadPropertyTag::ElementEnd);
                }
                Token::Text(text) => {
                    items.0.push(DeadPropertyTag::Text(text.into_owned()));
                }
                Token::Bytes(bytes) => {
                    items.0.push(DeadPropertyTag::Text(
                        String::from_utf8_lossy(&bytes).into_owned(),
                    ));
                }
                Token::Eof => {
                    break;
                }
            }
        }

        Ok(items)
    }
}

impl DeadProperty {
    pub fn remove_element(&mut self, element: &DeadElementTag) {
        let mut depth = 0;
        let mut remove = false;
        self.0.retain(|item| match item {
            DeadPropertyTag::ElementStart(tag) => {
                if depth == 0 && !remove && tag.name == element.name {
                    remove = true;
                }
                depth += 1;

                !remove
            }
            DeadPropertyTag::ElementEnd => {
                depth -= 1;
                if remove && depth == 0 {
                    remove = false;
                    false
                } else {
                    !remove
                }
            }
            _ => !remove,
        });
    }

    pub fn add_element(&mut self, element: DeadElementTag, values: Vec<DeadPropertyTag>) {
        self.0.push(DeadPropertyTag::ElementStart(element));
        self.0.extend(values);
        self.0.push(DeadPropertyTag::ElementEnd);
    }

    pub fn size(&self) -> usize {
        let mut size = 0;
        for item in &self.0 {
            match item {
                DeadPropertyTag::ElementStart(tag) => {
                    size += tag.size();
                }
                DeadPropertyTag::ElementEnd => {
                    size += 1;
                }
                DeadPropertyTag::Text(text) => {
                    size += text.len();
                }
            }
        }
        size
    }
}

impl ArchivedDeadProperty {
    pub fn size(&self) -> usize {
        let mut size = 0;
        for item in self.0.iter() {
            match item {
                ArchivedDeadPropertyTag::ElementStart(tag) => {
                    size += tag.size();
                }
                ArchivedDeadPropertyTag::ElementEnd => {
                    size += 1;
                }
                ArchivedDeadPropertyTag::Text(text) => {
                    size += text.len();
                }
            }
        }
        size
    }
}

impl DeadElementTag {
    pub fn new(name: String, attrs: Option<String>) -> Self {
        DeadElementTag { name, attrs }
    }

    pub fn size(&self) -> usize {
        self.name.len() + self.attrs.as_ref().map_or(0, |attrs| attrs.len())
    }
}

impl ArchivedDeadElementTag {
    pub fn size(&self) -> usize {
        self.name.len() + self.attrs.as_ref().map_or(0, |attrs| attrs.len())
    }
}

impl From<&RawElement<'_>> for DeadElementTag {
    fn from(raw: &RawElement<'_>) -> Self {
        let name = std::str::from_utf8(raw.element.local_name().as_ref())
            .unwrap_or("invalid-utf8")
            .trim_ascii()
            .to_string();
        let mut attrs = String::with_capacity(raw.element.attributes_raw().len());
        if let Some(namespace) = &raw.namespace {
            attrs.push_str("xmlns=\"");
            attrs.push_str(std::str::from_utf8(namespace).unwrap_or("invalid-utf8"));
            attrs.push('"');
        }

        for attr in raw.element.attributes().flatten() {
            if attr.key.as_ref() == b"xmlns" || attr.key.as_ref().starts_with(b"xmlns:") {
                // Skip namespace attributes
                continue;
            }
            if let (Ok(key), Ok(value)) = (
                std::str::from_utf8(attr.key.as_ref()),
                std::str::from_utf8(attr.value.as_ref()),
            ) {
                if !attrs.is_empty() {
                    attrs.push(' ');
                }
                attrs.push_str(key);
                attrs.push('=');
                attrs.push('"');
                attrs.push_str(value);
                attrs.push('"');
            }
        }

        DeadElementTag {
            name,
            attrs: (!attrs.is_empty()).then_some(attrs),
        }
    }
}

impl Default for DeadProperty {
    fn default() -> Self {
        DeadProperty(Vec::with_capacity(4))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        parser::{tokenizer::Tokenizer, DavParser},
        schema::request::{Acl, LockInfo, MkCol, PropFind, PropertyUpdate, Report},
    };

    #[test]
    fn parse_requests() {
        for entry in std::fs::read_dir("resources/requests").unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();

            if path.extension().map(|ext| ext == "xml").unwrap_or(false) {
                println!("Parsing: {:?}", path);
                let filename = path.file_name().unwrap().to_str().unwrap();
                let xml = std::fs::read_to_string(&path).unwrap();
                let mut tokenizer = Tokenizer::new(xml.as_bytes());

                let json_path = path.with_extension("json");
                let json_output = match filename.split_once('-').unwrap().0 {
                    "propfind" => match PropFind::parse(&mut tokenizer) {
                        Ok(propfind) => serde_json::to_string_pretty(&propfind).unwrap(),
                        Err(_) => String::new(),
                    },
                    "propertyupdate" => serde_json::to_string_pretty(
                        &PropertyUpdate::parse(&mut tokenizer).unwrap(),
                    )
                    .unwrap(),
                    "mkcol" => serde_json::to_string_pretty(&MkCol::parse(&mut tokenizer).unwrap())
                        .unwrap(),
                    "lockinfo" => {
                        serde_json::to_string_pretty(&LockInfo::parse(&mut tokenizer).unwrap())
                            .unwrap()
                    }
                    "report" => {
                        serde_json::to_string_pretty(&Report::parse(&mut tokenizer).unwrap())
                            .unwrap()
                    }
                    "acl" => {
                        serde_json::to_string_pretty(&Acl::parse(&mut tokenizer).unwrap()).unwrap()
                    }
                    _ => {
                        panic!("Unknown method: {}", filename);
                    }
                };

                /*if json_path.exists() {
                    let expected = std::fs::read_to_string(json_path).unwrap();
                    assert_eq!(json_output, expected);
                } else {*/
                std::fs::write(json_path, json_output).unwrap();
                //}
            }
        }
    }
}
