//! Closed, startup-only loading for compiled casework UI assets.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read},
    os::fd::{AsFd, OwnedFd},
    path::Path,
};

use rustix::fs::{openat, Mode, OFlags, CWD};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_ASSET_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct StaticAsset {
    pub content_type: &'static str,
    pub etag: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct StaticUi {
    index: StaticAsset,
    assets: BTreeMap<String, StaticAsset>,
}

impl StaticUi {
    /// Preload exactly `index.html` and the hashed build assets named by Vite's
    /// manifest. Every open is relative to an already opened directory and
    /// refuses symlinks. Requests never select a filesystem pathname.
    pub fn load(directory: &Path) -> io::Result<Self> {
        let root = openat(
            CWD,
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let index_bytes = read_regular_at(&root, "index.html", MAX_METADATA_BYTES)?;
        std::str::from_utf8(&index_bytes)
            .map_err(|_| invalid("compiled UI index.html is not UTF-8"))?;

        let vite = open_directory_at(&root, ".vite")?;
        let manifest_bytes = read_regular_at(&vite, "manifest.json", MAX_METADATA_BYTES)?;
        let manifest: Value = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| invalid(format!("invalid compiled UI manifest: {error}")))?;
        let entries = manifest
            .as_object()
            .ok_or_else(|| invalid("compiled UI manifest must be an object"))?;
        let mut names = BTreeSet::new();
        for entry in entries.values() {
            let object = entry
                .as_object()
                .ok_or_else(|| invalid("compiled UI manifest entry must be an object"))?;
            collect_string(object.get("file"), &mut names)?;
            collect_array(object.get("css"), &mut names)?;
            collect_array(object.get("assets"), &mut names)?;
        }
        if names.is_empty() {
            return Err(invalid("compiled UI manifest names no assets"));
        }

        let assets_directory = open_directory_at(&root, "assets")?;
        let mut assets = BTreeMap::new();
        for manifest_name in names {
            let filename = manifest_name
                .strip_prefix("assets/")
                .filter(|name| valid_filename(name))
                .ok_or_else(|| {
                    invalid(format!("invalid compiled UI asset name: {manifest_name}"))
                })?;
            let content_type = content_type(filename).ok_or_else(|| {
                invalid(format!("unsupported compiled UI asset type: {filename}"))
            })?;
            let bytes = read_regular_at(&assets_directory, filename, MAX_ASSET_BYTES)?;
            assets.insert(
                format!("/assets/{filename}"),
                StaticAsset {
                    content_type,
                    etag: etag(&bytes),
                    bytes,
                },
            );
        }

        Ok(Self {
            index: StaticAsset {
                content_type: "text/html; charset=utf-8",
                etag: etag(&index_bytes),
                bytes: index_bytes,
            },
            assets,
        })
    }

    pub fn response_asset(&self, path: &str) -> Option<&StaticAsset> {
        if path == "/" || is_declared_client_route(path) {
            return Some(&self.index);
        }
        self.assets.get(path)
    }
}

fn open_directory_at(directory: impl AsFd, name: &str) -> io::Result<OwnedFd> {
    Ok(openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?)
}

fn read_regular_at(directory: impl AsFd, name: &str, maximum: u64) -> io::Result<Vec<u8>> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let mut file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(invalid(format!(
            "compiled UI input is not a regular file: {name}"
        )));
    }
    let mut bytes = Vec::new();
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid(format!(
            "compiled UI input exceeds size limit: {name}"
        )));
    }
    Ok(bytes)
}

fn collect_string(value: Option<&Value>, names: &mut BTreeSet<String>) -> io::Result<()> {
    if let Some(value) = value {
        names.insert(
            value
                .as_str()
                .ok_or_else(|| invalid("compiled UI manifest file must be a string"))?
                .to_owned(),
        );
    }
    Ok(())
}

fn collect_array(value: Option<&Value>, names: &mut BTreeSet<String>) -> io::Result<()> {
    if let Some(value) = value {
        for entry in value
            .as_array()
            .ok_or_else(|| invalid("compiled UI manifest asset list must be an array"))?
        {
            names.insert(
                entry
                    .as_str()
                    .ok_or_else(|| invalid("compiled UI manifest asset name must be a string"))?
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn content_type(name: &str) -> Option<&'static str> {
    if name.ends_with(".js") {
        Some("text/javascript; charset=utf-8")
    } else if name.ends_with(".css") {
        Some("text/css; charset=utf-8")
    } else if name.ends_with(".svg") {
        Some("image/svg+xml")
    } else if name.ends_with(".png") {
        Some("image/png")
    } else if name.ends_with(".woff2") {
        Some("font/woff2")
    } else {
        None
    }
}

fn is_declared_client_route(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    if parts.first() != Some(&"") {
        return false;
    }
    if parts.get(1) == Some(&"operational-conditions") {
        if parts.as_slice() == ["", "operational-conditions"] {
            return true;
        }
        let Some(navigation_id) = parts.get(2) else {
            return false;
        };
        if navigation_id.len() != 64
            || !navigation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return false;
        }
        return match parts.as_slice() {
            ["", "operational-conditions", _] => true,
            ["", "operational-conditions", _, "raw"] => true,
            ["", "operational-conditions", _, "questions", id] => valid_route_id(id),
            _ => false,
        };
    }
    if parts.get(1) == Some(&"active-runs") {
        let Some(navigation_id) = parts.get(2) else {
            return false;
        };
        if navigation_id.len() != 64
            || !navigation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return false;
        }
        return match parts.as_slice() {
            ["", "active-runs", _] => true,
            ["", "active-runs", _, "events" | "raw"] => true,
            ["", "active-runs", _, "work-items" | "questions", id] => valid_route_id(id),
            _ => false,
        };
    }
    if parts.get(1) != Some(&"runs") {
        return false;
    }
    let Some(run_id) = parts.get(2) else {
        return false;
    };
    if run_id.len() != 64
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return false;
    }
    match parts.as_slice() {
        ["", "runs", _] => true,
        ["", "runs", _, "custody" | "raw"] => true,
        ["", "runs", _, "work-items" | "questions", id] => valid_route_id(id),
        _ => false,
    }
}

fn valid_route_id(id: &str) -> bool {
    !id.is_empty()
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'%' | b':')
        })
}

fn etag(bytes: &[u8]) -> String {
    format!("\"{:x}\"", Sha256::digest(bytes))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join(".vite")).unwrap();
        fs::create_dir(directory.path().join("assets")).unwrap();
        fs::write(
            directory.path().join("index.html"),
            br#"<!doctype html><script type="module" src="/assets/index-Ab12.js"></script>"#,
        )
        .unwrap();
        fs::write(
            directory.path().join(".vite/manifest.json"),
            br#"{"index.html":{"file":"assets/index-Ab12.js","css":["assets/index-Cd34.css"]}}"#,
        )
        .unwrap();
        fs::write(
            directory.path().join("assets/index-Ab12.js"),
            b"export {};\n",
        )
        .unwrap();
        fs::write(directory.path().join("assets/index-Cd34.css"), b"body {}\n").unwrap();
        directory
    }

    #[test]
    fn preloads_only_manifest_assets_and_declared_routes() {
        let directory = fixture();
        fs::write(directory.path().join("assets/not-listed.js"), b"not served").unwrap();
        let ui = StaticUi::load(directory.path()).unwrap();
        assert_eq!(
            ui.response_asset("/").unwrap().content_type,
            "text/html; charset=utf-8"
        );
        assert_eq!(
            ui.response_asset("/assets/index-Ab12.js").unwrap().bytes,
            b"export {};\n"
        );
        assert!(ui.response_asset("/assets/not-listed.js").is_none());
        let run = "0".repeat(64);
        assert!(ui.response_asset(&format!("/runs/{run}/custody")).is_some());
        assert!(ui
            .response_asset(&format!("/runs/{run}/anything-else"))
            .is_none());
        assert!(ui.response_asset("/../index.html").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_index_manifest_directory_and_asset() {
        use std::os::unix::fs::symlink;

        let directory = fixture();
        let index = directory.path().join("index.html");
        fs::remove_file(&index).unwrap();
        symlink("assets/index-Ab12.js", &index).unwrap();
        assert!(StaticUi::load(directory.path()).is_err());

        let directory = fixture();
        let vite = directory.path().join(".vite");
        let moved_vite = directory.path().join("moved-vite");
        fs::rename(&vite, &moved_vite).unwrap();
        symlink("moved-vite", &vite).unwrap();
        assert!(StaticUi::load(directory.path()).is_err());

        let directory = fixture();
        let asset = directory.path().join("assets/index-Ab12.js");
        fs::remove_file(&asset).unwrap();
        symlink("index-Cd34.css", &asset).unwrap();
        assert!(StaticUi::load(directory.path()).is_err());
    }
}
