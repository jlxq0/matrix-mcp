//! Per-volume Matrix device id, persisted on the PVC.
//!
//! ## Why this exists
//!
//! matrix-mcp advertises a single Matrix `device_id` in its OAuth
//! protected-resource metadata (`/.well-known/oauth-protected-resource`).
//! The advertised id ends up in the device-binding OAuth scope
//! claude.ai requests (`urn:matrix:org.matrix.msc2967.client:device:<id>`),
//! and Synapse uses it as the persistent device record name.
//!
//! Earlier iterations hard-coded the device id as a compile-time
//! constant (`MATRIXMCPCONNECTOR`, then `MATRIXMCP2`). That has a
//! sharp edge: **if the PVC ever gets wiped, the SDK regenerates its
//! ed25519 device keys but Synapse still remembers the old keys under
//! the same device id**. Every subsequent `/keys/upload` is rejected by
//! Synapse with `M_FORBIDDEN / SigningKeyChanged`, and the only recovery
//! is to ship a code change rotating the constant to a fresh id.
//!
//! Solution: persist the device id **on the PVC itself**, in a file
//! that lives next to the matrix-sdk `SQLite` stores. PVC and device id
//! live and die together. On first boot on a fresh PVC, we generate a
//! random id; on every subsequent boot we read it back. A PVC wipe
//! therefore *automatically* rotates the device id — no code change,
//! no operator action beyond reconnecting the claude.ai connector (its
//! cached device-binding scope no longer matches what we advertise, so
//! claude.ai re-fetches the well-known doc and re-does the OAuth dance
//! with the new scope).
//!
//! ## Format
//!
//! Generated ids look like `MATRIXMCP-XYZQ7K2P` — the `MATRIXMCP-` prefix
//! is a recognisable marker in Element's device list and MAS's session
//! list (helpful when an operator is hunting down stale records),
//! followed by 8 characters from a Crockford-base32-ish alphabet (no
//! `0`/`1`/`I`/`O` to avoid copy-paste ambiguity). Total length is 18
//! ASCII characters — well within Matrix's effectively-unlimited
//! `device_id` size, and short enough to remember.
//!
//! ## Bootstrap override
//!
//! For migrating an existing PVC whose stored matrix-sdk state was
//! associated with a previously-hard-coded device id, set the env var
//! `MATRIX_MCP_DEVICE_ID_BOOTSTRAP=<id>`. On a PVC that doesn't have
//! `.device-id` yet, the env value is written verbatim instead of a
//! random one. After the file has been written once, the env var is
//! ignored on subsequent boots (the file wins). The env var should be
//! removed from the deployment manifest after the first successful
//! boot — its only purpose is the one-shot migration.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::Rng;
use tracing::{info, warn};

/// Name of the file on the PVC root that stores this instance's
/// persistent Matrix device id.
const DEVICE_ID_FILENAME: &str = ".device-id";

/// Env var that supplies a one-shot bootstrap value for the device id.
/// See module docs for the migration story.
pub const ENV_BOOTSTRAP_DEVICE_ID: &str = "MATRIX_MCP_DEVICE_ID_BOOTSTRAP";

/// Maximum allowed length for the device id. Matrix's spec is effectively
/// unlimited, but we cap at a sensible value so a corrupted file with
/// runaway content can't bloat OAuth scope strings.
const MAX_DEVICE_ID_LEN: usize = 64;

/// Alphabet for the random suffix. Crockford-base32-ish: omits `0`, `1`,
/// `I`, `O` to keep ids unambiguous when read aloud or transcribed.
const RANDOM_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Length of the random suffix appended to `MATRIXMCP-`. 8 chars over
/// a 32-symbol alphabet gives ~40 bits of entropy — plenty for a
/// single-tenant or low-multi-tenant deployment to avoid collisions.
const RANDOM_SUFFIX_LEN: usize = 8;

/// Resolve the Matrix device id for this matrix-mcp instance.
///
/// Resolution order:
///
/// 1. If `<store_root>/.device-id` exists and contains a valid id, return that.
/// 2. Else, if `bootstrap_override` is `Some(non-empty)`, use that value.
/// 3. Else, generate a fresh random `MATRIXMCP-{suffix}` id.
///
/// In cases 2 and 3, the chosen id is **persisted to the file** before
/// being returned, so the next boot takes path 1.
///
/// Writes are atomic: the value is written to `.device-id.tmp` first,
/// then renamed over `.device-id`. A crash mid-write leaves either the
/// previous good file or no file — never a half-written one.
pub fn resolve_device_id(store_root: &Path, bootstrap_override: Option<&str>) -> Result<String> {
    fs::create_dir_all(store_root)
        .with_context(|| format!("create store root {}", store_root.display()))?;
    let path = store_root.join(DEVICE_ID_FILENAME);

    // Path 1: existing file.
    if path.exists() {
        let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let id = raw.trim();
        if validate_device_id(id) {
            info!(
                device_id = id,
                source = "pvc-file",
                "resolved Matrix device id"
            );
            return Ok(id.to_owned());
        }
        // Corrupted file: refuse to silently overwrite, surface clearly.
        warn!(
            path = %path.display(),
            content_len = raw.len(),
            "device-id file present but content failed validation; refusing to overwrite"
        );
        anyhow::bail!(
            "{} exists but contains an invalid device id; inspect/remove it manually",
            path.display()
        );
    }

    // Path 2: bootstrap override (one-shot migration). If absent or
    // empty/whitespace-only, fall through to Path 3 (random).
    let new_id =
        if let Some(override_id) = bootstrap_override.map(str::trim).filter(|s| !s.is_empty()) {
            if !validate_device_id(override_id) {
                anyhow::bail!(
                    "{ENV_BOOTSTRAP_DEVICE_ID}={override_id:?} is not a valid Matrix device id \
                 (must be 1..={MAX_DEVICE_ID_LEN} ASCII alphanumeric / `-` / `_`)"
                );
            }
            info!(
                device_id = override_id,
                source = "bootstrap-env",
                "writing bootstrap device id to PVC for first time"
            );
            override_id.to_owned()
        } else {
            // Path 3: generate fresh.
            let generated = generate_random_id();
            info!(
                device_id = %generated,
                source = "generated",
                "generated fresh random device id for this PVC"
            );
            generated
        };

    persist_atomic(&path, &new_id)?;
    Ok(new_id)
}

/// Write `content` to `path` atomically (write to `.tmp`, rename over).
fn persist_atomic(path: &Path, content: &str) -> Result<()> {
    let mut tmp_path: PathBuf = path.to_owned();
    let tmp_name = format!(
        "{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or(".tmp")
    );
    tmp_path.set_file_name(tmp_name);
    fs::write(&tmp_path, content)
        .with_context(|| format!("write temp file {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

/// Returns true if `s` is a valid device id per our own rules:
/// non-empty, length ≤ [`MAX_DEVICE_ID_LEN`], characters in `[A-Za-z0-9_-]`.
/// Matrix is more permissive but we're deliberately conservative so the
/// id is safe to embed in OAuth scopes, log lines, and filenames.
fn validate_device_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_DEVICE_ID_LEN
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Generate a random `MATRIXMCP-{8 chars}` id using OS entropy.
fn generate_random_id() -> String {
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity("MATRIXMCP-".len() + RANDOM_SUFFIX_LEN);
    s.push_str("MATRIXMCP-");
    for _ in 0..RANDOM_SUFFIX_LEN {
        let idx = rng.gen_range(0..RANDOM_ALPHABET.len());
        s.push(RANDOM_ALPHABET[idx] as char);
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generates_and_persists_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let id = resolve_device_id(tmp.path(), None).unwrap();
        assert!(id.starts_with("MATRIXMCP-"), "id={id}");
        assert_eq!(id.len(), "MATRIXMCP-".len() + RANDOM_SUFFIX_LEN);
        assert!(tmp.path().join(DEVICE_ID_FILENAME).exists());
    }

    #[test]
    fn reuses_existing_file_on_second_call() {
        let tmp = TempDir::new().unwrap();
        let first = resolve_device_id(tmp.path(), None).unwrap();
        let second = resolve_device_id(tmp.path(), None).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn bootstrap_override_used_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let id = resolve_device_id(tmp.path(), Some("MATRIXMCP2")).unwrap();
        assert_eq!(id, "MATRIXMCP2");
        let on_disk = fs::read_to_string(tmp.path().join(DEVICE_ID_FILENAME)).unwrap();
        assert_eq!(on_disk, "MATRIXMCP2");
    }

    #[test]
    fn bootstrap_override_ignored_when_file_present() {
        let tmp = TempDir::new().unwrap();
        let first = resolve_device_id(tmp.path(), Some("FIRST_VALUE")).unwrap();
        assert_eq!(first, "FIRST_VALUE");
        // Override is ignored on the second call because the file already exists.
        let second = resolve_device_id(tmp.path(), Some("SECOND_VALUE")).unwrap();
        assert_eq!(second, "FIRST_VALUE");
    }

    #[test]
    fn empty_bootstrap_override_falls_through_to_random() {
        let tmp = TempDir::new().unwrap();
        let id = resolve_device_id(tmp.path(), Some("")).unwrap();
        assert!(id.starts_with("MATRIXMCP-"));
    }

    #[test]
    fn whitespace_bootstrap_override_falls_through_to_random() {
        let tmp = TempDir::new().unwrap();
        let id = resolve_device_id(tmp.path(), Some("   ")).unwrap();
        assert!(id.starts_with("MATRIXMCP-"));
    }

    #[test]
    fn invalid_bootstrap_override_rejected() {
        let tmp = TempDir::new().unwrap();
        let err = resolve_device_id(tmp.path(), Some("has spaces")).unwrap_err();
        assert!(
            err.to_string().contains("not a valid Matrix device id"),
            "err={err}"
        );
        assert!(!tmp.path().join(DEVICE_ID_FILENAME).exists());
    }

    #[test]
    fn corrupted_existing_file_refuses_to_overwrite() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join(DEVICE_ID_FILENAME), "has bad chars!").unwrap();
        let err = resolve_device_id(tmp.path(), Some("OVERRIDE")).unwrap_err();
        assert!(err.to_string().contains("invalid"), "err={err}");
    }

    #[test]
    fn whitespace_in_file_is_trimmed() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join(DEVICE_ID_FILENAME), "MATRIXMCP2\n").unwrap();
        let id = resolve_device_id(tmp.path(), None).unwrap();
        assert_eq!(id, "MATRIXMCP2");
    }

    #[test]
    fn random_ids_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let tmp = TempDir::new().unwrap();
            let id = resolve_device_id(tmp.path(), None).unwrap();
            assert!(seen.insert(id), "random collision in 32 trials");
        }
    }

    #[test]
    fn random_id_alphabet_excludes_confusables() {
        let tmp = TempDir::new().unwrap();
        let id = resolve_device_id(tmp.path(), None).unwrap();
        let suffix = id.strip_prefix("MATRIXMCP-").unwrap();
        for c in suffix.chars() {
            assert!(
                !matches!(c, '0' | '1' | 'I' | 'O'),
                "found confusable {c:?} in {id}"
            );
        }
    }

    #[test]
    fn validate_device_id_unit() {
        assert!(validate_device_id("MATRIXMCP2"));
        assert!(validate_device_id("MATRIXMCP-XYZ"));
        assert!(validate_device_id("a"));
        assert!(validate_device_id(&"a".repeat(MAX_DEVICE_ID_LEN)));
        assert!(!validate_device_id(""));
        assert!(!validate_device_id(&"a".repeat(MAX_DEVICE_ID_LEN + 1)));
        assert!(!validate_device_id("has spaces"));
        assert!(!validate_device_id("has/slash"));
        assert!(!validate_device_id("has.dot"));
    }
}
