//! GeoIP / GeoSite database updates (Phase 12).
//!
//! Mirrors ShellCrash's geo data updater: fetch the latest release of a
//! rules repository (default MetaCubeX/meta-rules-dat) and download the
//! geosite/geoip assets into `<crash_dir>/bin/geodata` with atomic
//! replacement. A mirror prefix can redirect GitHub downloads to a CDN.

use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Default geodata source, same as ShellCrash.
pub const DEFAULT_GEO_REPO: &str = "MetaCubeX/meta-rules-dat";

const GITHUB_API: &str = "https://api.github.com";

#[derive(Debug, Deserialize)]
pub struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
pub struct Asset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug)]
pub struct GeoUpdateReport {
    pub repo: String,
    pub tag: String,
    pub updated: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub timestamp: DateTime<Utc>,
}

/// Should this release asset be installed as geodata? Mirrors ShellCrash's
/// filter: geosite*.dat, country*.mmdb, geoip*.metadb, *.mrs, *.srs.
pub fn is_geo_asset(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.starts_with("geosite") && lower.ends_with(".dat"))
        || (lower.starts_with("country") && lower.ends_with(".mmdb"))
        || (lower.starts_with("geoip") && lower.ends_with(".metadb"))
        || lower.ends_with(".mrs")
        || lower.ends_with(".srs")
}

/// Rewrite a GitHub download URL through a mirror prefix, e.g.
/// `https://ghproxy.example/https://github.com/...`.
pub fn mirror_url(url: &str, mirror: Option<&str>) -> String {
    match mirror.filter(|m| !m.is_empty()) {
        Some(m) => {
            let m = m.trim_end_matches('/');
            if url.starts_with(&format!("{m}/")) {
                url.to_string()
            } else {
                format!("{m}/{url}")
            }
        }
        None => url.to_string(),
    }
}

pub struct GeoUpdater {
    client: reqwest::Client,
    api_base: String,
}

impl GeoUpdater {
    pub fn new() -> Self {
        Self::with_api_base(GITHUB_API.to_string())
    }

    /// Constructor with an explicit API base (tests, proxies).
    pub fn with_api_base(api_base: String) -> Self {
        GeoUpdater {
            client: crate::notify::shared_client().clone(),
            api_base: api_base.trim_end_matches('/').to_string(),
        }
    }

    /// Fetch the latest release tag and geo assets of a repository.
    pub async fn latest_release(&self, repo: &str) -> Result<Release> {
        validate_repo(repo)?;
        let url = format!("{}/repos/{repo}/releases/latest", self.api_base);
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| Error::Download(format!("github api request failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Download(format!(
                "github api returned {} for {repo}",
                resp.status()
            )));
        }
        resp.json::<Release>()
            .await
            .map_err(|e| Error::Download(format!("github api decode failed: {e}")))
    }

    /// Download all geo assets of the latest release into `geodata_dir`,
    /// replacing files atomically (temp file + rename).
    pub async fn update(
        &self,
        geodata_dir: &Path,
        repo: &str,
        mirror: Option<&str>,
    ) -> Result<GeoUpdateReport> {
        let release = self.latest_release(repo).await?;
        std::fs::create_dir_all(geodata_dir)?;

        let mut report = GeoUpdateReport {
            repo: repo.to_string(),
            tag: release.tag_name.clone(),
            updated: Vec::new(),
            failed: Vec::new(),
            timestamp: Utc::now(),
        };

        for asset in &release.assets {
            if !is_geo_asset(&asset.name) {
                continue;
            }
            match self
                .download_asset(&asset.browser_download_url, mirror)
                .await
            {
                Ok(bytes) => match atomic_write(geodata_dir, &asset.name, &bytes) {
                    Ok(_path) => report.updated.push(asset.name.clone()),
                    Err(e) => report.failed.push((asset.name.clone(), e.to_string())),
                },
                Err(e) => report.failed.push((asset.name.clone(), e.to_string())),
            }
        }
        Ok(report)
    }

    async fn download_asset(&self, url: &str, mirror: Option<&str>) -> Result<Vec<u8>> {
        let effective = mirror_url(url, mirror);
        let bytes = self
            .client
            .get(&effective)
            .send()
            .await
            .map_err(|e| Error::Download(format!("asset download failed: {e}")))?
            .error_for_status()
            .map_err(|e| Error::Download(format!("asset download http error: {e}")))?
            .bytes()
            .await
            .map_err(|e| Error::Download(format!("asset read failed: {e}")))?;
        if bytes.is_empty() {
            return Err(Error::Download(format!("asset {url} is empty")));
        }
        Ok(bytes.to_vec())
    }
}

impl Default for GeoUpdater {
    fn default() -> Self {
        Self::new()
    }
}

/// Repo must be `owner/name` with safe characters — it is interpolated into
/// an API URL. Segments must not be empty, hidden or traversal-like.
fn validate_repo(repo: &str) -> Result<()> {
    let segments: Vec<&str> = repo.split('/').collect();
    let valid = segments.len() == 2
        && repo.len() <= 100
        && segments.iter().all(|s| {
            !s.is_empty()
                && !s.starts_with('.')
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(Error::Security(format!("invalid repository id: {repo}")))
    }
}

/// Write bytes to `dir/name` via a temp file + rename so a partial download
/// never replaces a good database.
fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    // Only the final component is used — asset names come from a remote API.
    let file_name = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Security(format!("unsafe asset name: {name}")))?;
    let final_path = dir.join(file_name);
    let tmp_path = dir.join(format!(".{file_name}.tmp"));
    std::fs::write(&tmp_path, bytes)?;
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_asset_filter() {
        assert!(is_geo_asset("GeoSite.dat"));
        assert!(is_geo_asset("geosite-lite.dat"));
        assert!(is_geo_asset("Country.mmdb"));
        assert!(is_geo_asset("geoip.metadb"));
        assert!(is_geo_asset("cn.mrs"));
        assert!(is_geo_asset("cn.srs"));
        assert!(!is_geo_asset("clash-linux-amd64.gz"));
        assert!(!is_geo_asset("checksums.txt"));
        assert!(!is_geo_asset("evil.sh"));
    }

    #[test]
    fn mirror_url_rewrite() {
        let url = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/v1/geosite.dat";
        assert_eq!(mirror_url(url, None), url);
        assert_eq!(
            mirror_url(url, Some("https://ghproxy.example/")),
            format!("https://ghproxy.example/{url}")
        );
        // Already-mirrored URLs are not double-prefixed.
        let mirrored = format!("https://ghproxy.example/{url}");
        assert_eq!(
            mirror_url(&mirrored, Some("https://ghproxy.example")),
            mirrored
        );
    }

    #[test]
    fn repo_validation() {
        assert!(validate_repo("MetaCubeX/meta-rules-dat").is_ok());
        assert!(validate_repo("a").is_err());
        assert!(validate_repo("a/b/c").is_err());
        assert!(validate_repo("a b/c").is_err());
        assert!(validate_repo("../evil").is_err());
    }

    #[test]
    fn atomic_write_sanitizes_traversal_names() {
        let tmp = tempfile::tempdir().unwrap();
        // Only the final component is used, so traversal stays inside dir.
        assert!(atomic_write(tmp.path(), "../evil.dat", b"x").is_ok());
        assert!(tmp.path().join("evil.dat").exists());
        assert!(!tmp.path().join("../evil.dat").exists());
        assert!(atomic_write(tmp.path(), "good.dat", b"x").is_ok());
        assert!(tmp.path().join("good.dat").exists());
    }

    #[tokio::test]
    async fn update_downloads_from_mock_release() {
        let server = wiremock::MockServer::start().await;

        // GitHub API response.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repos/test/geo/releases/latest"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "tag_name": "v20260101",
                    "assets": [
                        {"name": "GeoSite.dat", "browser_download_url": format!("{}/dl/GeoSite.dat", server.uri()), "size": 10},
                        {"name": "geoip.metadb", "browser_download_url": format!("{}/dl/geoip.metadb", server.uri()), "size": 10},
                        {"name": "clash-linux-amd64.gz", "browser_download_url": format!("{}/dl/skip.gz", server.uri()), "size": 10}
                    ]
                }),
            ))
            .mount(&server)
            .await;
        // Asset downloads.
        for name in ["GeoSite.dat", "geoip.metadb"] {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path(format!("/dl/{name}")))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("geodata-bytes"))
                .mount(&server)
                .await;
        }

        let updater = GeoUpdater::with_api_base(server.uri());
        let tmp = tempfile::tempdir().unwrap();
        let report = updater.update(tmp.path(), "test/geo", None).await.unwrap();

        assert_eq!(report.tag, "v20260101");
        assert_eq!(report.updated, vec!["GeoSite.dat", "geoip.metadb"]);
        assert!(report.failed.is_empty());
        assert_eq!(
            std::fs::read(tmp.path().join("GeoSite.dat")).unwrap(),
            b"geodata-bytes"
        );
        // Non-geo assets are skipped.
        assert!(!tmp.path().join("clash-linux-amd64.gz").exists());
        // No leftover temp files.
        assert!(std::fs::read_dir(tmp.path()).unwrap().count() == 2);
    }

    #[tokio::test]
    async fn download_asset_via_mirror() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(".*"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("db-bytes"))
            .mount(&server)
            .await;

        let updater = GeoUpdater::new();
        let bytes = updater
            .download_asset(
                "https://github.com/x/y/releases/download/v1/GeoSite.dat",
                Some(&server.uri()),
            )
            .await
            .unwrap();
        assert_eq!(bytes, b"db-bytes");
    }

    #[tokio::test]
    async fn download_asset_rejects_empty() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let updater = GeoUpdater::new();
        assert!(updater
            .download_asset("https://github.com/x", Some(&server.uri()))
            .await
            .is_err());
    }
}
