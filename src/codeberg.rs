use crate::error::AppError;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadStatus {
    Success(u16),
    AlreadyExists(String),
}

#[derive(Deserialize)]
struct UserResponse {
    login: String,
}

pub struct CodebergClient {
    client: Client,
}

impl CodebergClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { client }
    }

    pub fn verify_token(&self, host: &str, username: &str, token: &str) -> Result<(), AppError> {
        let base = if host.starts_with("http://") || host.starts_with("https://") {
            host.to_string()
        } else {
            format!("https://{host}")
        };
        let url = format!("{base}/api/v1/user");
        let response = self
            .client
            .get(&url)
            .basic_auth(username, Some(token))
            .send()
            .map_err(|e| AppError::TokenVerificationFailed {
                host: host.to_string(),
                message: format!("Connection error: {e}"),
            })?;

        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(AppError::AuthenticationRejected);
        }

        if !status.is_success() {
            let error_text = response.text().unwrap_or_default();
            return Err(AppError::TokenVerificationFailed {
                host: host.to_string(),
                message: format!("HTTP {status}: {}", sanitize_message(&error_text)),
            });
        }

        let body = response
            .text()
            .map_err(|e| AppError::TokenVerificationFailed {
                host: host.to_string(),
                message: format!("Failed reading response body: {e}"),
            })?;

        let user_info: UserResponse =
            serde_json::from_str(&body).map_err(|e| AppError::TokenVerificationFailed {
                host: host.to_string(),
                message: format!("Failed to parse user profile: {e}"),
            })?;

        if !user_info.login.eq_ignore_ascii_case(username) {
            return Err(AppError::TokenVerificationFailed {
                host: host.to_string(),
                message: format!(
                    "Token belongs to user '{}', but login was requested for '{}'",
                    user_info.login, username
                ),
            });
        }

        Ok(())
    }

    pub fn upload_package(
        &self,
        host: &str,
        owner: &str,
        group: &str,
        username: &str,
        token: &str,
        pkg_path: &Path,
    ) -> Result<UploadStatus, AppError> {
        let filename = pkg_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| pkg_path.display().to_string());

        let base = if host.starts_with("http://") || host.starts_with("https://") {
            host.to_string()
        } else {
            format!("https://{host}")
        };
        let url = format!("{base}/api/packages/{owner}/arch/{group}");

        let mut file = File::open(pkg_path).map_err(|e| AppError::ProcessExecution {
            cmd: format!("read package file {}", pkg_path.display()),
            source: e,
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let response = self
            .client
            .put(&url)
            .basic_auth(username, Some(token))
            .header("Content-Type", "application/octet-stream")
            .body(buffer)
            .send()
            .map_err(|e| AppError::UploadFailed {
                package: filename.clone(),
                status: 0,
                message: format!("Connection failed: {e}"),
            })?;

        let status = response.status();
        let body = response.text().unwrap_or_default();
        let sanitized = sanitize_message(&body);

        match status {
            StatusCode::CREATED | StatusCode::OK | StatusCode::NO_CONTENT => {
                Ok(UploadStatus::Success(status.as_u16()))
            }
            StatusCode::CONFLICT => Ok(UploadStatus::AlreadyExists(sanitized)),
            StatusCode::UNAUTHORIZED => Err(AppError::AuthenticationRejected),
            _ => Err(AppError::UploadFailed {
                package: filename,
                status: status.as_u16(),
                message: sanitized,
            }),
        }
    }
}

impl Default for CodebergClient {
    fn default() -> Self {
        Self::new()
    }
}

pub fn pacman_repo_url(host: &str, owner: &str, group: &str, arch: &str) -> String {
    format!("https://{host}/api/packages/{owner}/arch/{group}/{arch}")
}

fn sanitize_message(msg: &str) -> String {
    let trimmed = msg.trim();
    if trimmed.is_empty() {
        "No response body from server".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_pacman_repo_url_formatting() {
        let url = pacman_repo_url("codeberg.org", "nathawat", "x86-64-v3", "x86_64_v3");
        assert_eq!(
            url,
            "https://codeberg.org/api/packages/nathawat/arch/x86-64-v3/x86_64_v3"
        );
    }

    // Helper to spin up a single-response mock HTTP server
    fn run_mock_server(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                // Read request header lines until empty line
                while let Ok(n) = reader.read_line(&mut line) {
                    if n == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                    line.clear();
                }

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status_line,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        (format!("http://127.0.0.1:{}", addr.port()), handle)
    }

    #[test]
    fn test_mock_token_verify_success() {
        let (host, handle) = run_mock_server("200 OK", r#"{"login":"nathawat"}"#);
        let client = CodebergClient::new();
        let res = client.verify_token(&host, "nathawat", "dummy_token");
        assert!(res.is_ok());
        let _ = handle.join();
    }

    #[test]
    fn test_mock_token_verify_username_mismatch() {
        let (host, handle) = run_mock_server("200 OK", r#"{"login":"different_user"}"#);
        let client = CodebergClient::new();
        let res = client.verify_token(&host, "nathawat", "dummy_token");
        assert!(matches!(res, Err(AppError::TokenVerificationFailed { .. })));
        let _ = handle.join();
    }

    #[test]
    fn test_mock_token_verify_unauthorized() {
        let (host, handle) =
            run_mock_server("401 Unauthorized", r#"{"message":"bad credentials"}"#);
        let client = CodebergClient::new();
        let res = client.verify_token(&host, "nathawat", "bad_token");
        assert!(matches!(res, Err(AppError::AuthenticationRejected)));
        let _ = handle.join();
    }

    #[test]
    fn test_mock_upload_success_201() {
        let (host, handle) = run_mock_server("201 Created", "Package uploaded");
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_file = temp_dir.path().join("pkg-1.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&pkg_file, b"fake package data").unwrap();

        let client = CodebergClient::new();
        let res = client.upload_package(
            &host,
            "nathawat",
            "x86-64",
            "nathawat",
            "dummy_token",
            &pkg_file,
        );
        assert_eq!(res.unwrap(), UploadStatus::Success(201));
        let _ = handle.join();
    }

    #[test]
    fn test_mock_upload_conflict_409() {
        let (host, handle) = run_mock_server("409 Conflict", "Package already exists");
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_file = temp_dir.path().join("pkg-1.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&pkg_file, b"fake package data").unwrap();

        let client = CodebergClient::new();
        let res = client.upload_package(
            &host,
            "nathawat",
            "x86-64",
            "nathawat",
            "dummy_token",
            &pkg_file,
        );
        assert_eq!(
            res.unwrap(),
            UploadStatus::AlreadyExists("Package already exists".to_string())
        );
        let _ = handle.join();
    }

    #[test]
    fn test_mock_upload_server_error_500() {
        let (host, handle) = run_mock_server("500 Internal Server Error", "Database error");
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_file = temp_dir.path().join("pkg-1.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&pkg_file, b"fake package data").unwrap();

        let client = CodebergClient::new();
        let res = client.upload_package(
            &host,
            "nathawat",
            "x86-64",
            "nathawat",
            "dummy_token",
            &pkg_file,
        );
        assert!(matches!(
            res,
            Err(AppError::UploadFailed { status: 500, .. })
        ));
        let _ = handle.join();
    }

    #[test]
    fn test_sanitize_message_empty() {
        assert_eq!(sanitize_message("   "), "No response body from server");
    }
}
