use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("locales.rs");

    // Read the YAML file
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let repo_root = Path::new(&manifest_dir).parent().unwrap().parent().unwrap();
    let yaml_path = repo_root.join("resources/locales/i18n.yml");
    let yaml_content =
        fs::read_to_string(&yaml_path).unwrap_or_else(|_| panic!("Failed to read {yaml_path:?}"));

    let locales = parse_yaml(&yaml_content);

    let generated_code = generate_locale_code(&locales);

    fs::write(&dest_path, generated_code).expect("Failed to write generated locales");

    println!("cargo:rerun-if-changed={yaml_path:?}");
}

fn parse_yaml(content: &str) -> HashMap<String, HashMap<String, String>> {
    let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current_key = None;

    for line in content.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let is_translation = key
                .as_bytes()
                .first()
                .is_some_and(|&b| b.is_ascii_whitespace());
            let key = key.trim();
            if !key.starts_with('#') && !key.is_empty() {
                if !is_translation {
                    current_key = result.entry(key.replace('.', "_")).or_default().into();
                } else {
                    current_key
                        .as_mut()
                        .unwrap()
                        .insert(key.to_string(), value.trim().trim_matches('"').to_string());
                }
            }
        }
    }

    result
}

fn generate_locale_code(locales: &HashMap<String, HashMap<String, String>>) -> String {
    let mut code = String::new();

    code.push_str("#[derive(Debug, Clone)]\n");
    code.push_str("pub struct Locale {\n");

    for key in locales.keys() {
        code.push_str(&format!("    pub {}: &'static str,\n", key));
    }

    code.push_str("}\n\n");

    let mut languages = std::collections::HashSet::new();
    for translations in locales.values() {
        for lang in translations.keys() {
            languages.insert(lang.clone());
        }
    }

    for lang in &languages {
        code.push_str(&format!(
            "pub static {}_LOCALES: Locale = Locale {{\n",
            lang.to_uppercase()
        ));

        for (key, translations) in locales {
            let value = translations
                .get(lang)
                .unwrap_or_else(|| panic!("Missing: {}", key));
            code.push_str(&format!("    {key}: {value:?},\n"));
        }

        code.push_str("};\n\n");
    }

    code.push_str("pub fn locale(name: &str) -> Option<&'static Locale> {\n");
    code.push_str("    hashify::tiny_map!(name.as_bytes(),\n");
    for lang in &languages {
        code.push_str(&format!(
            "        \"{}\" => &{}_LOCALES,\n",
            lang,
            lang.to_uppercase()
        ));
    }
    code.push_str("    )\n");
    code.push_str("}\n");
    code
}
