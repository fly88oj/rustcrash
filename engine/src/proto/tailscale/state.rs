//! The ipn state store: machine + node key persistence in the tsnet
//! state file.
//!
//! Port of `tailscale.com/ipn/store/stores.go`'s `FileStore` (cached at
//! `/tmp/wave11-upstream/ipn_store_stores.go`) plus the key-loading half
//! of `LocalBackend.initMachineKeyLocked` (ipn/ipnlocal/local.go:
//! 4481-4516, cached `ipn_ipnlocal_local.go`) and tsnet's state file
//! placement (tsnet/tsnet.go:957: `filepath.Join(s.rootPath,
//! "tailscaled.state")`).
//!
//! NOTE on the wave's reference pointer: the task cites `ipn/ipn_state.go`,
//! which no longer exists upstream — the state machinery now lives in
//! `ipn/store.go` (the `StateStore` interface + the well-known state
//! keys, cached `ipn_store.go`) and `ipn/store/stores.go` (the JSON
//! `FileStore`). Those are the files cited here.
//!
//! # The file format
//!
//! `FileStore` is a JSON object `map[StateKey][]byte` (stores.go:155-216):
//! Go marshals `[]byte` values as base64 strings, so the on-disk shape is
//!
//! ```json
//! {
//!   "_machinekey": "base64(privkey:<64 hex>)"
//! }
//! ```
//!
//! with 0600 perms, written atomically (`atomicfile.WriteFile`,
//! stores.go:210-216 — the port writes a temp file and renames). An empty
//! file is treated as missing (stores.go:175-179, tailscale issue #895),
//! and a missing file is initialized to `{}` (stores.go:183-190).
//!
//! # Keys stored
//!
//! * `_machinekey` — `ipn.MachineKeyStateKey` (ipn/store.go:28-30): the
//!   value is `key.MachinePrivate.MarshalText` = `"privkey:<hex>"`
//!   (types/key/machine.go:24, 75-79). Load-or-generate is exactly
//!   `initMachineKeyLocked` (local.go:4494-4516).
//! * `_daemon` — `ipn.LegacyGlobalDaemonStateKey` (ipn/store.go:40-46):
//!   the pre-profiles global state key. Its value is the
//!   `persist.Persist` JSON (types/persist/persist.go:21-40); this port
//!   stores the two fields it needs — `PrivateNodeKey` and
//!   `OldPrivateNodeKey`, both `privkey:` text — under the `"Config"`
//!   json name `Prefs.Persist` uses (ipn/prefs.go:314-319).
//!
//! Ephemeral nodes (`Ephemeral: true`) keep everything in memory only —
//! they must leave no state behind (direct.go:766 `Ephemeral` flag).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::derp::NodePrivateKey;
use super::noise::MachinePrivateKey;
use super::tailcfg::{node_private_from_text, node_private_text};

/// `ipn.MachineKeyStateKey` (ipn/store.go:28-30).
pub const MACHINE_KEY_STATE_KEY: &str = "_machinekey";

/// `ipn.LegacyGlobalDaemonStateKey` (ipn/store.go:40-46) — where the
/// pre-profiles Persist blob lived; still the simplest faithful slot for
/// a single-profile tsnet-style node.
pub const LEGACY_GLOBAL_DAEMON_STATE_KEY: &str = "_daemon";

/// The state file name inside the state dir (tsnet.go:957).
pub const STATE_FILE_NAME: &str = "tailscaled.state";

/// The `persist.Persist` fields this port persists (persist.go:24-25),
/// under Prefs' json name for the field, `"Config"` (prefs.go:319).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Persist {
    /// `PrivateNodeKey` — the node's WireGuard-protocol key (the key
    /// peers and DERP know), `privkey:` text form.
    #[serde(rename = "PrivateNodeKey", default)]
    pub private_node_key: String,
    /// `OldPrivateNodeKey` — "needed to request key rotation"
    /// (persist.go:25).
    #[serde(rename = "OldPrivateNodeKey", default)]
    pub old_private_node_key: String,
}

/// The JSON file store — `FileStore` (stores.go:155-216). Values are
/// base64 strings on disk (Go `[]byte`), decoded here to bytes.
#[derive(Debug, Default)]
pub struct FileStore {
    path: PathBuf,
    cache: BTreeMap<String, Vec<u8>>,
}

impl FileStore {
    /// `NewFileStore` (stores.go:164-216): create the state dir, treat an
    /// empty file as missing, initialize a missing file to `{}`.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<FileStore> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let bs = match std::fs::read(&path) {
            Ok(bs) => bs,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Write out an initial file, to verify that we can write
                // to the path (stores.go:183-190).
                atomic_write(&path, b"{}", 0o600)?;
                return Ok(FileStore {
                    path,
                    cache: BTreeMap::new(),
                });
            }
            Err(e) => return Err(e),
        };
        if bs.is_empty() {
            // stores.go:175-179.
            atomic_write(&path, b"{}", 0o600)?;
            return Ok(FileStore {
                path,
                cache: BTreeMap::new(),
            });
        }
        let raw: BTreeMap<String, String> = serde_json::from_slice(&bs)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut cache = BTreeMap::new();
        for (k, v) in raw {
            // Values are base64 (Go []byte); a stray non-base64 value is
            // a corrupt store, surfaced as InvalidData like json.Unmarshal
            // failures upstream.
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(v.as_bytes())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            cache.insert(k, bytes);
        }
        Ok(FileStore { path, cache })
    }

    /// `ReadState` (stores.go:219-227): `None` = `ErrStateNotExist`.
    pub fn read_state(&self, id: &str) -> Option<&[u8]> {
        self.cache.get(id).map(|v| v.as_slice())
    }

    /// `WriteState` (stores.go:229-244): update the cache and rewrite the
    /// whole file atomically; a `None` value deletes the key.
    pub fn write_state(&mut self, id: &str, value: Option<&[u8]>) -> std::io::Result<()> {
        match value {
            Some(v) => self.cache.insert(id.to_string(), v.to_vec()),
            None => self.cache.remove(id),
        };
        let raw: BTreeMap<&str, String> = self
            .cache
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str(),
                    base64::engine::general_purpose::STANDARD.encode(v),
                )
            })
            .collect();
        let json = serde_json::to_vec_pretty(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        atomic_write(&self.path, &json, 0o600)
    }
}

/// `atomicfile.WriteFile` (util/atomicfile/file.go): write to a temp file
/// in the same directory, fsync, rename over the target — a reader never
/// observes a torn state file.
fn atomic_write(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("state"),
        std::process::id()
    ));
    {
        use std::os::unix::fs::PermissionsExt;
        let mut f = std::fs::File::create(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// The node's key material: the machine identity for the control noise
/// session and the node key for the data plane.
#[derive(Debug)]
pub struct NodeIdentity {
    pub machine_key: MachinePrivateKey,
    pub node_key: NodePrivateKey,
}

impl NodeIdentity {
    /// Load-or-create the identity from `state_dir` (or generate a fully
    /// ephemeral one).
    ///
    /// Machine key: `initMachineKeyLocked` (local.go:4481-4516) — read
    /// `_machinekey`, else generate and persist.
    ///
    /// Node key: read the Persist JSON under `_daemon`; when absent
    /// generate a fresh node key (direct.go:711-713 "Generating a new
    /// nodekey") and persist it. Ephemeral mode never touches the disk.
    pub fn load_or_generate(state_dir: Option<&Path>, ephemeral: bool) -> std::io::Result<Self> {
        if ephemeral || state_dir.is_none() {
            return Ok(NodeIdentity {
                machine_key: MachinePrivateKey::generate(),
                node_key: NodePrivateKey::generate(),
            });
        }
        let dir = state_dir.unwrap();
        let mut store = FileStore::open(dir.join(STATE_FILE_NAME))?;

        // Machine key (local.go:4487-4516).
        let machine_key = match store.read_state(MACHINE_KEY_STATE_KEY) {
            Some(text) => {
                let text = String::from_utf8_lossy(text).into_owned();
                MachinePrivateKey::from_hex(
                    text.strip_prefix("privkey:").unwrap_or(&text),
                )
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "invalid key in {MACHINE_KEY_STATE_KEY}: {e}"
                    ))
                })?
            }
            None => {
                let key = MachinePrivateKey::generate();
                let text = format!("privkey:{}", key.to_hex());
                store.write_state(MACHINE_KEY_STATE_KEY, Some(text.as_bytes()))?;
                key
            }
        };

        // Node key (Persist under the legacy global key).
        let node_key = match store.read_state(LEGACY_GLOBAL_DAEMON_STATE_KEY) {
            Some(raw) => {
                let persist: Persist = serde_json::from_slice(raw).map_err(|e| {
                    std::io::Error::other(format!("invalid Persist state: {e}"))
                })?;
                node_private_from_text(&persist.private_node_key).ok_or_else(|| {
                    std::io::Error::other("invalid PrivateNodeKey in state")
                })?
            }
            None => {
                let key = NodePrivateKey::generate();
                let persist = Persist {
                    private_node_key: node_private_text(&key),
                    old_private_node_key: String::new(),
                };
                let raw = serde_json::to_vec(&persist).map_err(std::io::Error::other)?;
                store.write_state(LEGACY_GLOBAL_DAEMON_STATE_KEY, Some(raw.as_slice()))?;
                key
            }
        };

    Ok(NodeIdentity {
        machine_key,
        node_key,
    })
}
}

/// Commit a rotated node key to the state store — the persist half of
/// the key-expiry renewal: "key rotation is complete:
/// `persist.PrivateNodeKey = tryingNewKey`" (direct.go:876-879), with
/// `OldPrivateNodeKey` kept ("needed to request key rotation",
/// persist.go:24-25) so a FUTURE rotation can present this one as the
/// old key. Ephemeral nodes and missing state dirs are a no-op (there
/// is nothing to persist).
pub fn persist_rotated_node_key(
    state_dir: Option<&Path>,
    new: &NodePrivateKey,
    old: Option<&NodePrivateKey>,
) -> std::io::Result<()> {
    let Some(dir) = state_dir else {
        return Ok(());
    };
    let mut store = FileStore::open(dir.join(STATE_FILE_NAME))?;
    // Preserve whatever else the Persist blob carried (read-modify-write).
    let mut persist = match store.read_state(LEGACY_GLOBAL_DAEMON_STATE_KEY) {
        Some(raw) => serde_json::from_slice::<Persist>(raw)
            .map_err(|e| std::io::Error::other(format!("invalid Persist state: {e}")))?,
        None => Persist::default(),
    };
    persist.old_private_node_key = old.map(node_private_text).unwrap_or_default();
    persist.private_node_key = node_private_text(new);
    let raw = serde_json::to_vec(&persist).map_err(std::io::Error::other)?;
    store.write_state(LEGACY_GLOBAL_DAEMON_STATE_KEY, Some(raw.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_round_trips_and_is_created_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let mut store = FileStore::open(&path).unwrap();
        assert!(store.read_state("_missing").is_none());
        store.write_state("_k", Some(b"value")).unwrap();
        // Reopen: the JSON + base64 shape survives (FileStore semantics).
        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(reopened.read_state("_k"), Some(&b"value"[..]));
        // The on-disk bytes are the documented shape: pretty JSON, base64
        // values, 0600.
        let raw = std::fs::read(&path).unwrap();
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains("\"_k\""), "{text}");
        assert!(text.contains("dmFsdWU="), "base64(value) must be on disk: {text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Delete semantics (WriteState nil).
        let mut store = FileStore::open(&path).unwrap();
        store.write_state("_k", None).unwrap();
        assert!(FileStore::open(&path).unwrap().read_state("_k").is_none());
    }

    #[test]
    fn empty_state_file_is_treated_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        std::fs::write(&path, b"").unwrap();
        let store = FileStore::open(&path).unwrap();
        assert!(store.read_state("_k").is_none());
        // And it was re-initialized to a valid empty store.
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw, b"{}");
    }

    #[test]
    fn corrupt_state_file_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        std::fs::write(&path, b"not json at all").unwrap();
        assert!(FileStore::open(&path).is_err());
    }

    #[test]
    fn identity_loads_or_generates_and_persists_across_restarts() {
        let dir = tempfile::tempdir().unwrap();

        // First boot: both keys generated and persisted.
        let id1 = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        // Machine key: privkey: text under _machinekey (base64 wrapper is
        // the FileStore's).
        let store = FileStore::open(dir.path().join(STATE_FILE_NAME)).unwrap();
        let mk = String::from_utf8_lossy(store.read_state(MACHINE_KEY_STATE_KEY).unwrap())
            .into_owned();
        assert_eq!(mk, format!("privkey:{}", id1.machine_key.to_hex()));
        let persist_raw = store.read_state(LEGACY_GLOBAL_DAEMON_STATE_KEY).unwrap();
        let persist: Persist = serde_json::from_slice(persist_raw).unwrap();
        assert_eq!(persist.private_node_key, node_private_text(&id1.node_key));

        // Second boot: same identity (a node must not rotate its keys on
        // restart or the tailnet forgets it).
        let id2 = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        assert_eq!(id2.machine_key.to_hex(), id1.machine_key.to_hex());
        assert_eq!(id2.node_key.public(), id1.node_key.public());

        // Ephemeral: in-memory only, nothing written, fresh keys.
        let dir2 = tempfile::tempdir().unwrap();
        let e1 = NodeIdentity::load_or_generate(Some(dir2.path()), true).unwrap();
        assert!(!dir2.path().join(STATE_FILE_NAME).exists());
        let e2 = NodeIdentity::load_or_generate(Some(dir2.path()), true).unwrap();
        assert_ne!(e1.node_key.public(), e2.node_key.public());
        assert_ne!(e1.machine_key.to_hex(), e2.machine_key.to_hex());
    }

    #[test]
    fn tampered_machine_key_state_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = FileStore::open(dir.path().join(STATE_FILE_NAME)).unwrap();
            store
                .write_state(MACHINE_KEY_STATE_KEY, Some(b"privkey:zzzz"))
                .unwrap();
        }
        let err = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap_err();
        assert!(err.to_string().contains("invalid key"));
    }

    #[test]
    fn rotated_node_key_persists_and_reloads() {
        // The renewal's state half (direct.go:876-879 + persist.go:24-25):
        // the new key lands in PrivateNodeKey, the old one moves to
        // OldPrivateNodeKey, and a restart loads the NEW identity.
        let dir = tempfile::tempdir().unwrap();
        let first = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let fresh = NodePrivateKey::generate();
        persist_rotated_node_key(Some(dir.path()), &fresh, Some(&first.node_key)).unwrap();

        let store = FileStore::open(dir.path().join(STATE_FILE_NAME)).unwrap();
        let persist: Persist =
            serde_json::from_slice(store.read_state(LEGACY_GLOBAL_DAEMON_STATE_KEY).unwrap())
                .unwrap();
        assert_eq!(persist.private_node_key, node_private_text(&fresh));
        assert_eq!(persist.old_private_node_key, node_private_text(&first.node_key));

        let reloaded = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        assert_eq!(reloaded.node_key.public(), fresh.public());
        assert_eq!(reloaded.machine_key.to_hex(), first.machine_key.to_hex());

        // No state dir: a no-op, never an error, nothing written.
        persist_rotated_node_key(None, &fresh, None).unwrap();
    }
}
