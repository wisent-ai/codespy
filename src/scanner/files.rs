//! Which files a scan reads, and the language each one is.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde::Deserialize;

/// The file-type table: extensions per language, exact names, and the
/// directories a scan never enters.
const TABLE: &str = include_str!("languages.json");
/// A file larger than this many bytes is not read.
pub const MAX_FILE_SIZE: u64 = 1_000_000;

#[derive(Deserialize)]
struct Table {
    extensions: HashMap<String, Vec<String>>,
    named_files: HashMap<String, String>,
    dockerfile_prefix: String,
    skip_directories: Vec<String>,
}

static LANGUAGES: LazyLock<Table> =
    LazyLock::new(|| serde_json::from_str(TABLE).expect("the file-type table is valid JSON"));

/// The language of a file from its name, or `None` when a scan does not
/// read that kind of file.
pub fn detect_language(path: &Path) -> Option<&'static str> {
    let table: &'static Table = &LANGUAGES;
    let name = path.file_name()?.to_str()?;
    if let Some(language) = table.named_files.get(name) {
        return Some(language.as_str());
    }
    if name.starts_with(&table.dockerfile_prefix) {
        return table.named_files.get("Dockerfile").map(String::as_str);
    }
    let extension = format!(".{}", path.extension()?.to_str()?.to_lowercase());
    table
        .extensions
        .iter()
        .find(|(_, extensions)| extensions.contains(&extension))
        .map(|(language, _)| language.as_str())
}

fn skipped_directory(name: &str) -> bool {
    name.starts_with('.') || LANGUAGES.skip_directories.iter().any(|skipped| skipped == name)
}

/// Every file under `root` a scan reads, with its language. A single file is
/// read when its language is known; a directory is walked without following
/// directory links, skipping hidden and build directories and files larger
/// than [`MAX_FILE_SIZE`].
pub fn collect_files(root: &Path) -> io::Result<Vec<(PathBuf, &'static str)>> {
    let mut files = Vec::new();
    if root.is_file() {
        if let Some(language) = detect_language(root) {
            files.push((root.to_path_buf(), language));
        }
        return Ok(files);
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                let name = entry.file_name();
                if !skipped_directory(&name.to_string_lossy()) {
                    pending.push(path);
                }
                continue;
            }
            let Some(language) = detect_language(&path) else { continue };
            // A file that vanished or cannot be measured is not read, as a
            // file the walk could not open is not.
            let Ok(metadata) = fs::metadata(&path) else { continue };
            if metadata.len() <= MAX_FILE_SIZE {
                files.push((path, language));
            }
        }
    }
    Ok(files)
}
