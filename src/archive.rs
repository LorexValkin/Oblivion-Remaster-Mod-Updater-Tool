use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use unrar::VolumeInfo;
use walkdir::WalkDir;

pub const MAX_ARCHIVE_ENTRIES: usize = 250_000;
pub const MAX_ARCHIVE_DECLARED_BYTES: u64 = 128 * 1024 * 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex(&digest.finalize())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    // Keep the streaming buffer off the Windows executable's 1 MiB main
    // thread stack. The GUI normally calls this work from a spawned thread,
    // but native console entry points use the smaller linker-default stack.
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

pub fn sha256_directory(path: &Path) -> Result<String> {
    let mut rows = Vec::new();
    for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(path)?
            .to_string_lossy()
            .replace('\\', "/");
        rows.push(format!("{}\t{}", relative, sha256_file(entry.path())?));
    }
    rows.sort();
    let mut digest = Sha256::new();
    digest.update(rows.join("\n").as_bytes());
    Ok(hex(&digest.finalize()))
}

fn is_safe_relative(path: &Path) -> bool {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return false;
    }
    path.components().all(|component| match component {
        Component::CurDir => true,
        Component::Normal(segment) => {
            let segment = segment.to_string_lossy();
            if segment.is_empty()
                || segment.contains(':')
                || segment.ends_with('.')
                || segment.ends_with(' ')
            {
                return false;
            }
            let stem = segment
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && stem.as_bytes()[3].is_ascii_digit()
                    && stem.as_bytes()[3] != b'0')
        }
        _ => false,
    })
}

#[derive(Clone, Debug)]
pub struct RarEntryMetadata {
    pub path: PathBuf,
    pub unpacked_size: u64,
    pub is_directory: bool,
}

fn rar_link_like(file_attr: u32) -> bool {
    const WINDOWS_REPARSE_POINT: u32 = 0x0400;
    const UNIX_FILE_TYPE_MASK: u32 = 0xf000;
    const UNIX_DIRECTORY: u32 = 0x4000;
    const UNIX_REGULAR_FILE: u32 = 0x8000;
    let unix_type = file_attr & UNIX_FILE_TYPE_MASK;
    file_attr & WINDOWS_REPARSE_POINT != 0
        || (unix_type != 0 && unix_type != UNIX_DIRECTORY && unix_type != UNIX_REGULAR_FILE)
}

pub fn rar_entries(source: &Path) -> Result<Vec<RarEntryMetadata>> {
    let mut archive = unrar::Archive::new(source)
        .open_for_listing()
        .with_context(|| format!("reading RAR metadata {}", source.display()))?;
    if archive.volume_info() != VolumeInfo::None {
        bail!("multipart RAR archives are not supported; provide a single-volume .rar archive");
    }
    if archive.has_encrypted_headers() {
        bail!("password-protected RAR archives are not supported");
    }
    let mut entries = Vec::new();
    let mut declared_bytes = 0_u64;
    let mut seen = HashSet::new();
    for result in &mut archive {
        let entry = result.with_context(|| format!("listing RAR {}", source.display()))?;
        if entries.len() >= MAX_ARCHIVE_ENTRIES {
            bail!("RAR contains more than {} entries", MAX_ARCHIVE_ENTRIES);
        }
        if entry.is_split() {
            bail!(
                "split RAR entries are not supported: {}",
                entry.filename.display()
            );
        }
        if entry.is_encrypted() {
            bail!(
                "password-protected RAR entries are not supported: {}",
                entry.filename.display()
            );
        }
        if rar_link_like(entry.file_attr) {
            bail!(
                "RAR contains a filesystem link or special file: {}",
                entry.filename.display()
            );
        }
        if !is_safe_relative(&entry.filename) {
            bail!("RAR contains unsafe path: {}", entry.filename.display());
        }
        let key = entry
            .filename
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if !seen.insert(key) {
            bail!(
                "RAR contains a duplicate path: {}",
                entry.filename.display()
            );
        }
        if entry.is_file() {
            declared_bytes = declared_bytes
                .checked_add(entry.unpacked_size)
                .context("RAR declared size overflow")?;
            if declared_bytes > MAX_ARCHIVE_DECLARED_BYTES {
                bail!(
                    "RAR declares {declared_bytes} unpacked bytes; limit is {MAX_ARCHIVE_DECLARED_BYTES}"
                );
            }
        }
        let is_directory = entry.is_directory();
        entries.push(RarEntryMetadata {
            path: entry.filename,
            unpacked_size: entry.unpacked_size,
            is_directory,
        });
    }
    Ok(entries)
}

fn extract_rar(source: &Path, destination: &Path) -> Result<()> {
    let expected = rar_entries(source)?;
    let staged = tempfile::Builder::new()
        .prefix("obr-rar-extract-")
        .tempdir()?;
    let mut archive = unrar::Archive::new(source)
        .open_for_processing()
        .with_context(|| format!("opening RAR for extraction {}", source.display()))?;
    if archive.volume_info() != VolumeInfo::None {
        bail!("multipart RAR archives are not supported");
    }
    let mut index = 0_usize;
    loop {
        let Some(cursor) = archive
            .read_header()
            .with_context(|| format!("reading RAR entry {}", source.display()))?
        else {
            break;
        };
        let entry = cursor.entry();
        let filename = entry.filename.clone();
        let unpacked_size = entry.unpacked_size;
        let is_directory = entry.is_directory();
        let is_encrypted = entry.is_encrypted();
        let is_split = entry.is_split();
        let file_attr = entry.file_attr;
        let expected_entry = expected
            .get(index)
            .context("RAR entry count changed between validation and extraction")?;
        if filename != expected_entry.path
            || unpacked_size != expected_entry.unpacked_size
            || is_directory != expected_entry.is_directory
            || !is_safe_relative(&filename)
            || is_encrypted
            || is_split
            || rar_link_like(file_attr)
        {
            bail!(
                "RAR entry metadata changed after validation: {}",
                filename.display()
            );
        }
        let target = staged.path().join(&filename);
        archive = if is_directory {
            fs::create_dir_all(&target)?;
            cursor.skip()
        } else {
            fs::create_dir_all(target.parent().context("RAR file has no parent")?)?;
            cursor.extract_to(&target)
        }
        .with_context(|| format!("extracting RAR entry {}", filename.display()))?;
        index += 1;
    }
    if index != expected.len() {
        bail!(
            "RAR entry count changed between validation and extraction: expected {}, processed {}",
            expected.len(),
            index
        );
    }
    copy_tree(staged.path(), destination)
}

fn extract_zip(source: &Path, destination: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(File::open(source)?)
        .with_context(|| format!("reading ZIP {}", source.display()))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        bail!(
            "ZIP contains {} entries; limit is {}",
            archive.len(),
            MAX_ARCHIVE_ENTRIES
        );
    }
    let mut declared_bytes = 0_u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        entry
            .enclosed_name()
            .filter(|path| is_safe_relative(path))
            .with_context(|| format!("archive contains unsafe path: {}", entry.name()))?;
        if !entry.is_dir() {
            declared_bytes = declared_bytes
                .checked_add(entry.size())
                .context("ZIP declared size overflow")?;
        }
    }
    if declared_bytes > MAX_ARCHIVE_DECLARED_BYTES {
        bail!(
            "ZIP declares {declared_bytes} unpacked bytes; limit is {MAX_ARCHIVE_DECLARED_BYTES}"
        );
    }
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let relative = entry
            .enclosed_name()
            .filter(|path| is_safe_relative(path))
            .with_context(|| format!("archive contains unsafe path: {}", entry.name()))?
            .to_path_buf();
        let target = destination.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        fs::create_dir_all(target.parent().context("archive file has no parent")?)?;
        let mut output = BufWriter::new(File::create(&target)?);
        io::copy(&mut entry, &mut output)?;
        output.flush()?;
    }
    Ok(())
}

fn extract_7z(source: &Path, destination: &Path) -> Result<()> {
    let reader = sevenz_rust::SevenZReader::open(source, sevenz_rust::Password::empty())
        .with_context(|| format!("reading 7Z metadata {}", source.display()))?;
    if reader.archive().files.len() > MAX_ARCHIVE_ENTRIES {
        bail!(
            "7Z contains {} entries; limit is {}",
            reader.archive().files.len(),
            MAX_ARCHIVE_ENTRIES
        );
    }
    let mut declared_bytes = 0_u64;
    for entry in &reader.archive().files {
        let relative = Path::new(entry.name());
        if !is_safe_relative(relative) {
            bail!("archive contains unsafe path: {}", entry.name());
        }
        if !entry.is_directory() {
            declared_bytes = declared_bytes
                .checked_add(entry.size())
                .context("7Z declared size overflow")?;
        }
    }
    if declared_bytes > MAX_ARCHIVE_DECLARED_BYTES {
        bail!("7Z declares {declared_bytes} unpacked bytes; limit is {MAX_ARCHIVE_DECLARED_BYTES}");
    }
    drop(reader);
    let mut unsafe_name = None::<String>;
    sevenz_rust::decompress_file_with_extract_fn(source, destination, |entry, reader, target| {
        let relative = Path::new(entry.name());
        if !is_safe_relative(relative) {
            unsafe_name = Some(entry.name().to_owned());
            io::copy(reader, &mut io::sink()).map_err(sevenz_rust::Error::io)?;
            return Ok(true);
        }
        sevenz_rust::default_entry_extract_fn(entry, reader, target)
    })
    .with_context(|| format!("extracting 7Z {}", source.display()))?;
    if let Some(name) = unsafe_name {
        bail!("archive contains unsafe path: {name}");
    }
    Ok(())
}

pub fn extract_archive(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    match source
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "zip" => extract_zip(source, destination),
        "7z" => extract_7z(source, destination),
        "rar" => extract_rar(source, destination),
        extension => bail!("unsupported archive extension: {extension}"),
    }
}

pub fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    for entry in WalkDir::new(source) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            fs::create_dir_all(target.parent().context("copied file has no parent")?)?;
            fs::copy(entry.path(), &target).with_context(|| {
                format!("copying {} to {}", entry.path().display(), target.display())
            })?;
        } else {
            bail!(
                "archive tree contains unsupported link: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

pub fn copy_input_tree(source: &Path, destination: &Path) -> Result<()> {
    if source.is_dir() {
        let leaf = source.file_name().context("input directory has no name")?;
        copy_tree(source, &destination.join(leaf))
    } else {
        extract_archive(source, destination)
    }
}

pub fn create_zip_from_paths(output: &Path, root: &Path, paths: &[PathBuf]) -> Result<()> {
    let file = File::create(output).with_context(|| format!("creating {}", output.display()))?;
    let mut writer = zip::ZipWriter::new(BufWriter::new(file));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let directory_options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);
    let mut entries = Vec::new();
    for path in paths {
        if path.is_dir() {
            for entry in WalkDir::new(path) {
                let entry = entry?;
                entries.push(entry.path().to_path_buf());
            }
        } else {
            entries.push(path.clone());
        }
    }
    entries.sort();
    entries.dedup();
    for path in entries {
        let relative = path.strip_prefix(root).with_context(|| {
            format!("{} is outside ZIP root {}", path.display(), root.display())
        })?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let name = relative.to_string_lossy().replace('\\', "/");
        if path.is_dir() {
            writer.add_directory(format!("{name}/"), directory_options)?;
        } else {
            writer.start_file(name, options)?;
            let mut input = BufReader::new(File::open(&path)?);
            io::copy(&mut input, &mut writer)?;
        }
    }
    writer.finish()?.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_digest_is_stable() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.txt"), b"a").unwrap();
        fs::create_dir(temp.path().join("nested")).unwrap();
        fs::write(temp.path().join("nested/b.txt"), b"b").unwrap();
        assert_eq!(
            sha256_directory(temp.path()).unwrap(),
            sha256_directory(temp.path()).unwrap()
        );
    }

    #[test]
    fn zip_is_fully_validated_before_any_file_is_extracted() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("unsafe.zip");
        let file = File::create(&archive_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("safe.txt", options).unwrap();
        writer.write_all(b"safe").unwrap();
        writer.start_file("../escape.txt", options).unwrap();
        writer.write_all(b"escape").unwrap();
        writer.finish().unwrap();

        let destination = temp.path().join("output");
        assert!(extract_archive(&archive_path, &destination).is_err());
        assert!(!destination.join("safe.txt").exists());
        assert!(!temp.path().join("escape.txt").exists());
    }

    #[test]
    fn archive_paths_reject_windows_aliases_and_streams() {
        assert!(!is_safe_relative(Path::new("NUL.txt")));
        assert!(!is_safe_relative(Path::new("safe/file.txt:stream")));
        assert!(!is_safe_relative(Path::new("safe/trailing. ")));
        assert!(is_safe_relative(Path::new("safe/nested/file.txt")));
    }

    #[test]
    fn rar_attributes_reject_links_and_special_unix_files() {
        assert!(rar_link_like(0x0400));
        assert!(rar_link_like(0xa000 | 0o777));
        assert!(rar_link_like(0x6000 | 0o644));
        assert!(!rar_link_like(0x8000 | 0o644));
        assert!(!rar_link_like(0x4000 | 0o755));
        assert!(!rar_link_like(0x20));
    }

    #[test]
    #[ignore = "requires OBR_TEST_RAR to point to a local single-volume RAR fixture"]
    fn extracts_local_rar_fixture() {
        let source = std::env::var_os("OBR_TEST_RAR")
            .map(PathBuf::from)
            .expect("missing OBR_TEST_RAR");
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("output");
        extract_archive(&source, &output).unwrap();
        assert!(
            WalkDir::new(&output)
                .into_iter()
                .filter_map(Result::ok)
                .any(|entry| entry.file_type().is_file())
        );
    }
}
