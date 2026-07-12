use std::path::PathBuf;

fn main() {
    let manifest_path = PathBuf::from("reference-plugin/manifest.toml");
    println!("cargo:rerun-if-changed={}", manifest_path.display());

    let manifest_text = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", manifest_path.display()));
    let manifest: toml::Value = toml::from_str(&manifest_text)
        .unwrap_or_else(|error| panic!("parsing {}: {error}", manifest_path.display()));
    let embedding = manifest
        .get("embedding_provider")
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| {
            panic!(
                "{} has no embedding_provider table",
                manifest_path.display()
            )
        });
    let model = embedding
        .get("model")
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("{} has no embedding model", manifest_path.display()));
    let dimensions = embedding
        .get("dimensions")
        .and_then(toml::Value::as_integer)
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            panic!(
                "{} has no positive embedding dimensions",
                manifest_path.display()
            )
        });

    let generated = format!(
        "pub const MODEL_ID: &str = {model:?};\npub const DIMENSIONS: usize = {dimensions};\n"
    );
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"))
        .join("reference_manifest.rs");
    std::fs::write(&output, generated)
        .unwrap_or_else(|error| panic!("writing {}: {error}", output.display()));
}
