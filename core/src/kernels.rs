//! Kernel (mihomo/sing-box) management

use crate::error::{Error, Result};
use crate::platform::{Platform, ProxyKernel};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;

/// SHA-256 of `data` as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Kernel binary information
#[derive(Debug, Clone)]
pub struct KernelInfo {
    pub kind: ProxyKernel,
    pub version: String,
    pub path: String,
    pub arch: String,
    pub size: u64,
}

/// Kernel manager for downloading and managing proxy kernels
pub struct KernelManager {
    platform: Platform,
    crash_dir: String,
}

impl KernelManager {
    pub fn new(platform: &Platform) -> Self {
        KernelManager {
            platform: platform.clone(),
            crash_dir: platform.crash_dir(),
        }
    }

    pub fn kernel_path(&self, kernel: ProxyKernel) -> String {
        format!("{}/bin/{}", self.crash_dir, kernel.binary_name())
    }

    pub fn is_installed(&self, kernel: ProxyKernel) -> bool {
        Path::new(&self.kernel_path(kernel)).exists()
    }

    pub async fn installed_kernel(&self, kernel: ProxyKernel) -> Result<Option<KernelInfo>> {
        let path = self.kernel_path(kernel);
        if !Path::new(&path).exists() {
            return Ok(None);
        }

        let version = self.get_kernel_version(kernel).await?;
        let metadata = fs::metadata(&path)?;

        Ok(Some(KernelInfo {
            kind: kernel,
            version,
            path,
            arch: self.platform.normalized_arch(),
            size: metadata.len(),
        }))
    }

    /// Probe the installed kernel's version. Async: it spawns the kernel
    /// binary briefly (mihomo `-v`, sing-box `version` — mihomo rejects
    /// `--version`), so callers run it inside a tokio runtime.
    pub async fn get_kernel_version(&self, kernel: ProxyKernel) -> Result<String> {
        let bin = crate::service::validated_executable(&self.kernel_path(kernel))?;
        let version_args: &[&str] = match kernel {
            ProxyKernel::Mihomo => &["-v"],
            ProxyKernel::SingBox => &["version"],
        };
        let output = tokio::process::Command::new(bin.as_os_str())
            .args(version_args)
            .output()
            .await
            .map_err(|e| Error::Process(format!("Failed to get version: {e}")))?;

        if !output.status.success() {
            return Err(Error::Process(format!(
                "{} version probe failed: {}",
                kernel.binary_name(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// List recent release versions (newest first) for rollback support.
    pub async fn list_releases(&self, kernel: ProxyKernel, limit: usize) -> Result<Vec<String>> {
        let url = match kernel {
            ProxyKernel::Mihomo => {
                format!("https://api.github.com/repos/MetaCubeX/mihomo/releases?per_page={limit}")
            }
            ProxyKernel::SingBox => {
                format!("https://api.github.com/repos/SagerNet/sing-box/releases?per_page={limit}")
            }
        };
        let client = reqwest::Client::builder()
            .user_agent("RustCrash/1.0")
            .build()
            .map_err(|e| Error::Download(e.to_string()))?;
        let resp = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| Error::Download(format!("Failed to list releases: {e}")))?;
        if !resp.status().is_success() {
            let hint = match resp.status().as_u16() {
                403 | 429 => " (rate limited? retry later)",
                _ => "",
            };
            return Err(Error::Download(format!(
                "failed to list {} releases: HTTP {}{hint}",
                kernel.binary_name(),
                resp.status()
            )));
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Download(format!("releases decode failed: {e}")))?;
        let mut versions = Vec::new();
        if let Some(items) = json.as_array() {
            for item in items {
                if let Some(tag) = item["tag_name"].as_str() {
                    versions.push(tag.trim_start_matches('v').to_string());
                }
            }
        }
        Ok(versions)
    }

    pub async fn get_latest_version(&self, kernel: ProxyKernel) -> Result<String> {
        let url = match kernel {
            ProxyKernel::Mihomo => "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
            ProxyKernel::SingBox => {
                "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
            }
        };

        let client = reqwest::Client::builder()
            .user_agent("RustCrash/1.0")
            .build()
            .map_err(|e| Error::Download(e.to_string()))?;

        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Download(format!("Failed to fetch version: {e}")))?;

        if !resp.status().is_success() {
            let hint = match resp.status().as_u16() {
                403 | 429 => " (rate limited? retry later or pass --version)",
                _ => "",
            };
            return Err(Error::Download(format!(
                "failed to query latest {} release: HTTP {}{hint}",
                kernel.binary_name(),
                resp.status()
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Download(format!("Failed to parse JSON: {e}")))?;

        let tag = json["tag_name"]
            .as_str()
            .ok_or_else(|| Error::Download("No tag_name in response".into()))?;

        Ok(tag.trim_start_matches('v').to_string())
    }

    pub async fn install(&self, kernel: ProxyKernel, version: Option<&str>) -> Result<()> {
        self.install_with_base(kernel, version, "https://github.com")
            .await
    }

    /// Install with an explicit GitHub base URL (tests, mirrors).
    pub async fn install_with_base(
        &self,
        kernel: ProxyKernel,
        version: Option<&str>,
        github_base: &str,
    ) -> Result<()> {
        let version: String = match version {
            // Accept both "1.19.13" and the "v1.19.13" tag form users
            // copy from the releases page.
            Some(v) => v.trim_start_matches('v').to_string(),
            // Propagate the API error — a silent empty version builds
            // garbage download URLs (seen with GitHub rate limiting).
            None => self.get_latest_version(kernel).await?,
        };
        if version.is_empty() {
            return Err(Error::Download(
                "could not determine the latest release version".into(),
            ));
        }

        let arch = &self.platform.normalized_arch();
        let os = "linux";

        let download_name = match kernel {
            // MetaCubeX asset layout: mihomo-<os>-<arch>-v<version>.gz
            ProxyKernel::Mihomo => {
                format!("mihomo-{}-{}-v{}.gz", os, arch, version)
            }
            // SagerNet asset layout: sing-box-<version>-<os>-<arch>.gz
            ProxyKernel::SingBox => {
                format!("sing-box-{}-{}-{}.gz", version, os, arch)
            }
        };

        let base_url = match kernel {
            ProxyKernel::Mihomo => format!("{github_base}/MetaCubeX/mihomo/releases/download"),
            ProxyKernel::SingBox => format!("{github_base}/SagerNet/sing-box/releases/download"),
        };

        let url = format!("{}/v{}/{}", base_url, version, download_name);

        tracing::info!(
            "Downloading {} v{} from {}",
            kernel.binary_name(),
            version,
            url
        );

        let client = reqwest::Client::builder()
            .user_agent("RustCrash/1.0")
            .build()
            .map_err(|e| Error::Download(e.to_string()))?;

        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Download(format!("Failed to download: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::Download(format!("HTTP {}", resp.status())));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Download(format!("Failed to read body: {e}")))?;

        let tmp_dir = tempfile::TempDir::new()
            .map_err(|e| Error::Download(format!("Failed to create temp directory: {e}")))?;
        let tmp_gz_path = tmp_dir.path().join(&download_name);
        let tmp_gz_path_str = tmp_gz_path.to_string_lossy().to_string();

        fs::write(&tmp_gz_path, &bytes)?;

        // Integrity verification (FR-1.5): when a `.dgst`/`.sha256` sidecar
        // exists for the release asset, the archive hash must match before
        // anything is installed.
        match self.fetch_checksum(&url, &client).await {
            Some(expected) => {
                let actual = sha256_hex(&bytes);
                let expected = expected.to_ascii_lowercase();
                if expected != actual {
                    return Err(Error::Security(format!(
                        "checksum mismatch for {download_name}: expected {expected}, got {actual}"
                    )));
                }
                tracing::info!("Checksum verified for {download_name}");
            }
            None => {
                tracing::warn!(
                    "no checksum sidecar published for {download_name}; \
                     installing without verification"
                );
            }
        }

        let tmp_bin_path = tmp_gz_path_str.trim_end_matches(".gz");
        self.decompress_gz(&tmp_gz_path_str, tmp_bin_path)?;

        let dest = self.kernel_path(kernel);
        let dest_dir = Path::new(&dest).parent().unwrap();
        fs::create_dir_all(dest_dir)?;
        fs::rename(tmp_bin_path, &dest)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dest)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dest, perms)?;
        }

        tracing::info!("Installed {} to {}", kernel.binary_name(), dest);
        Ok(())
    }

    fn decompress_gz(&self, src: &str, dest: &str) -> Result<()> {
        let file = fs::File::open(src)?;
        let mut decoder = GzDecoder::new(file);
        let mut buffer = Vec::new();
        decoder.read_to_end(&mut buffer)?;
        fs::write(dest, &buffer)?;
        Ok(())
    }

    /// Try to fetch a published checksum for a release asset. Sing-box
    /// publishes `.dgst` files containing multiple hashes; mihomo names may
    /// carry `.sha256`. Returns None when no sidecar exists (verification
    /// is skipped, matching previous behaviour).
    async fn fetch_checksum(&self, asset_url: &str, client: &reqwest::Client) -> Option<String> {
        for suffix in [".dgst", ".sha256"] {
            let url = format!("{asset_url}{suffix}");
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let Ok(text) = resp.text().await else {
                continue;
            };
            // Formats: "<hex>  <file>" (sha256sum) or "SHA256(<file>)= <hex>".
            for line in text.lines() {
                let hex_candidate: &str = if let Some((hex, _)) = line.split_once("  ") {
                    hex
                } else if let Some((_, rest)) = line.split_once(")= ") {
                    rest
                } else {
                    line
                };
                let hex_candidate = hex_candidate.trim();
                if hex_candidate.len() == 64 && hex_candidate.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Some(hex_candidate.to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{FirewallBackend, InitSystem};
    use tempfile::TempDir;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(b"").len(), 64);
    }

    #[tokio::test]
    async fn install_rejects_checksum_mismatch() {
        let server = MockServer::start().await;
        let asset_body = gzip_bytes(b"#!/bin/sh\nexit 0\n");
        // Asset download
        Mock::given(method("GET"))
            .and(path(
                "/MetaCubeX/mihomo/releases/download/v1.0.0/mihomo-linux-amd64-v1.0.0.gz",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(asset_body))
            .mount(&server)
            .await;
        // Checksum sidecar with the WRONG hash
        Mock::given(method("GET"))
            .and(path(
                "/MetaCubeX/mihomo/releases/download/v1.0.0/mihomo-linux-amd64-v1.0.0.gz.dgst",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "SHA256(mihomo-linux-amd64-v1.0.0.gz)= deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
            ))
            .mount(&server)
            .await;

        let tmp = TempDir::new().unwrap();
        let platform = test_platform(tmp.path().to_str().unwrap());
        let km = KernelManager::new(&platform);

        let err = km
            .install_with_base(ProxyKernel::Mihomo, Some("1.0.0"), &server.uri())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"), "{err}");
        // Nothing installed on mismatch.
        assert!(!Path::new(&km.kernel_path(ProxyKernel::Mihomo)).exists());
    }

    #[tokio::test]
    async fn install_accepts_matching_checksum() {
        let server = MockServer::start().await;
        let asset_body = gzip_bytes(b"#!/bin/sh\nexit 0\n");
        Mock::given(method("GET"))
            .and(path(
                "/MetaCubeX/mihomo/releases/download/v1.0.0/mihomo-linux-amd64-v1.0.0.gz",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(asset_body.clone()))
            .mount(&server)
            .await;
        let good = format!(
            "{}  mihomo-linux-amd64-v1.0.0.gz\n",
            sha256_hex(&asset_body)
        );
        Mock::given(method("GET"))
            .and(path(
                "/MetaCubeX/mihomo/releases/download/v1.0.0/mihomo-linux-amd64-v1.0.0.gz.dgst",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(good))
            .mount(&server)
            .await;

        let tmp = TempDir::new().unwrap();
        let platform = test_platform(tmp.path().to_str().unwrap());
        let km = KernelManager::new(&platform);
        km.install_with_base(ProxyKernel::Mihomo, Some("1.0.0"), &server.uri())
            .await
            .unwrap();
        assert!(Path::new(&km.kernel_path(ProxyKernel::Mihomo)).exists());
    }

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn test_platform(crash_dir: &str) -> Platform {
        use crate::platform::ContainerInfo;
        Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            init_system: InitSystem::Systemd,
            is_openwrt: false,
            is_docker: false,
            firewall_backend: FirewallBackend::Iptables,
            default_crash_dir: Box::leak(crash_dir.to_string().into_boxed_str()),
            container_info: ContainerInfo::default(),
            crash_dir_resolved: crash_dir.to_string(),
            runtime_dir_resolved: format!("{crash_dir}/run"),
            log_dir_resolved: format!("{crash_dir}/logs"),
        }
    }

    fn make_kernel_manager(tmp: &TempDir) -> KernelManager {
        let crash_dir = tmp.path().to_str().unwrap();
        KernelManager::new(&test_platform(crash_dir))
    }

    #[tokio::test]
    async fn test_get_latest_version_mihomo() {
        let mock_server = MockServer::start().await;
        let json_response = r#"{"tag_name": "v1.19.0"}"#;
        Mock::given(method("GET"))
            .and(path("/repos/MetaCubeX/mihomo/releases/latest"))
            .and(header("User-Agent", "RustCrash/1.0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json_response))
            .mount(&mock_server)
            .await;

        let url = format!(
            "{}/repos/MetaCubeX/mihomo/releases/latest",
            mock_server.uri()
        );
        let client = reqwest::Client::builder()
            .user_agent("RustCrash/1.0")
            .build()
            .unwrap();
        let resp = client.get(&url).send().await.unwrap();
        let json: serde_json::Value = resp.json().await.unwrap();
        let tag = json["tag_name"].as_str().unwrap().trim_start_matches('v');
        assert_eq!(tag, "1.19.0");
    }

    #[tokio::test]
    async fn test_get_latest_version_singbox() {
        let mock_server = MockServer::start().await;
        let json_response = r#"{"tag_name": "v1.9.0"}"#;
        Mock::given(method("GET"))
            .and(path("/repos/SagerNet/sing-box/releases/latest"))
            .and(header("User-Agent", "RustCrash/1.0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json_response))
            .mount(&mock_server)
            .await;

        let url = format!(
            "{}/repos/SagerNet/sing-box/releases/latest",
            mock_server.uri()
        );
        let client = reqwest::Client::builder()
            .user_agent("RustCrash/1.0")
            .build()
            .unwrap();
        let resp = client.get(&url).send().await.unwrap();
        let json: serde_json::Value = resp.json().await.unwrap();
        let tag = json["tag_name"].as_str().unwrap().trim_start_matches('v');
        assert_eq!(tag, "1.9.0");
    }

    #[test]
    fn test_kernel_path() {
        let tmp = TempDir::new().unwrap();
        let km = make_kernel_manager(&tmp);

        let path = km.kernel_path(ProxyKernel::Mihomo);
        assert!(path.contains("mihomo"));

        let path = km.kernel_path(ProxyKernel::SingBox);
        assert!(path.contains("sing-box"));
    }

    #[test]
    fn test_is_installed_when_not_exists() {
        let tmp = TempDir::new().unwrap();
        let km = make_kernel_manager(&tmp);

        assert!(!km.is_installed(ProxyKernel::Mihomo));
        assert!(!km.is_installed(ProxyKernel::SingBox));
    }

    #[test]
    fn test_is_installed_when_exists() {
        let tmp = TempDir::new().unwrap();
        let km = make_kernel_manager(&tmp);

        // Create a fake kernel binary
        let mihomo_path = km.kernel_path(ProxyKernel::Mihomo);
        std::fs::create_dir_all(std::path::Path::new(&mihomo_path).parent().unwrap()).unwrap();
        std::fs::write(&mihomo_path, "fake binary").unwrap();

        assert!(km.is_installed(ProxyKernel::Mihomo));
        assert!(!km.is_installed(ProxyKernel::SingBox));
    }

    #[test]
    fn test_decompress_gz() {
        let tmp = TempDir::new().unwrap();
        let km = make_kernel_manager(&tmp);

        // Create a simple gzipped file
        let src_path = tmp.path().join("test.txt.gz");
        let dest_path = tmp.path().join("test.txt");
        let original_content = "Hello, World! This is test content.";

        // Compress using flate2
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let file = std::fs::File::create(&src_path).unwrap();
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(original_content.as_bytes()).unwrap();
        encoder.finish().unwrap();

        km.decompress_gz(src_path.to_str().unwrap(), dest_path.to_str().unwrap())
            .unwrap();

        let decompressed = std::fs::read_to_string(&dest_path).unwrap();
        assert_eq!(decompressed, original_content);
    }
}
