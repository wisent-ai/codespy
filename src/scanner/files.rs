//! Which files a scan reads, and the language each one is.

use std::collections::HashMap;
use std::fs;
use std::io;

use super::ScanError;
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

/// Every language a scan reads, with the file suffixes that select it. Only
/// suffixes are listed: a bare name in the extension table never equals a
/// suffix, so it opens nothing.
pub fn scanned_suffixes() -> impl Iterator<Item = (&'static str, Vec<&'static str>)> {
    let table: &'static Table = &LANGUAGES;
    table.extensions.iter().map(|(language, extensions)| {
        let suffixes = extensions.iter().filter(|name| name.starts_with('.')).map(String::as_str).collect();
        (language.as_str(), suffixes)
    })
}

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
/// than [`MAX_FILE_SIZE`]. A directory or file the walk cannot open or
/// measure is an error naming it, never a silent gap in the scan.
pub fn collect_files(root: &Path) -> Result<Vec<(PathBuf, &'static str)>, ScanError> {
    let walk = |path: &Path, error: io::Error| ScanError::Walk { path: path.to_path_buf(), error };
    let mut files = Vec::new();
    if root.is_file() {
        if let Some(language) = detect_language(root) {
            files.push((root.to_path_buf(), language));
        }
        return Ok(files);
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| walk(&directory, error))? {
            let entry = entry.map_err(|error| walk(&directory, error))?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| walk(&path, error))?;
            if kind.is_dir() {
                let name = entry.file_name();
                if !skipped_directory(&name.to_string_lossy()) {
                    pending.push(path);
                }
                continue;
            }
            let Some(language) = detect_language(&path) else { continue };
            let metadata = fs::metadata(&path).map_err(|error| walk(&path, error))?;
            if metadata.len() <= MAX_FILE_SIZE {
                files.push((path, language));
            }
        }
    }
    Ok(files)
}
