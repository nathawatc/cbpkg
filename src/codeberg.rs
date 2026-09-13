use crate::error::AppError;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadStatus {
    Success(u16),
    AlreadyExists(String),
}

pub struct CodebergClient {
    client: Client,
    allow_insecure_http: bool,
}

impl CodebergClient {
    pub fn new() -> Result<Self, AppError> {
        Self::with_options(false)
    }

    fn with_options(allow_insecure_http: bool) -> Result<Self, AppError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .https_only(!allow_insecure_http)
            .build()
            .map_err(|e| AppError::HttpClientInit(e.to_string()))?;
        Ok(Self {
            client,
            allow_insecure_http,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_test_client() -> Result<Self, AppError> {
        Self::with_options(true)
    }

    fn normalize_endpoint(&self, host: &str) -> Result<String, AppError> {
        let trimmed = host.trim().trim_end_matches('/');
        if trimmed.starts_with("http://") {
            if !self.allow_insecure_http {
                return Err(AppError::InsecureHttpRejected(trimmed.to_string()));
            }
            Ok(trimmed.to_string())
        } else if trimmed.starts_with("https://") {
            Ok(trimmed.to_string())
        } else {
            Ok(format!("https://{trimmed}"))
        }
    }

    pub fn verify_token(&self, host: &str, username: &str, token: &str) -> Result<(), AppError> {
        let base = self.normalize_endpoint(host)?;
        let url = format!("{base}/api/v1/packages/{username}?limit=1");
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

        if status == StatusCode::NOT_FOUND {
            return Err(AppError::TokenVerificationFailed {
                host: host.to_string(),
                message: format!("Package owner '{username}' not found on {host}"),
            });
        }

        if !status.is_success() {
            let sanitized = read_and_sanitize_response(response, token);
            return Err(AppError::TokenVerificationFailed {
                host: host.to_string(),
                message: format!("HTTP {status}: {sanitized}"),
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

        let base = self.normalize_endpoint(host)?;
        let url = format!("{base}/api/packages/{owner}/arch/{group}");

        let file = File::open(pkg_path).map_err(|e| AppError::ProcessExecution {
            cmd: format!("open package file {}", pkg_path.display()),
            source: e,
        })?;

        let metadata = file.metadata().map_err(|e| AppError::ProcessExecution {
            cmd: format!("stat package file {}", pkg_path.display()),
            source: e,
        })?;
        let file_len = metadata.len();

        let response = self
            .client
            .put(&url)
            .basic_auth(username, Some(token))
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", file_len)
            .body(file)
            .send()
            .map_err(|e| AppError::UploadFailed {
                package: filename.clone(),
                status: 0,
                message: format!("Connection failed: {e}"),
            })?;

        let status = response.status();
        let sanitized = read_and_sanitize_response(response, token);

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

pub fn pacman_repo_url(host: &str, owner: &str, group: &str, arch: &str) -> String {
    let clean_host = host
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    format!("https://{clean_host}/api/packages/{owner}/arch/{group}/{arch}")
}

pub const MAX_ERROR_BODY_BYTES: usize = 1024;
pub const MIN_LOOKAHEAD_BYTES: usize = 256;
pub const MAX_LOOKAHEAD_BYTES: usize = 65536;
pub const OVERSIZED_TOKEN_SUPPRESSED_MSG: &str = "Server returned an error response; body suppressed because credential length exceeds safe redaction window.";

pub fn read_and_sanitize_response<R: Read>(mut reader: R, token: &str) -> String {
    if token.len() > MAX_LOOKAHEAD_BYTES {
        return OVERSIZED_TOKEN_SUPPRESSED_MSG.to_string();
    }
    let lookahead = if token.is_empty() {
        MIN_LOOKAHEAD_BYTES
    } else {
        token.len().clamp(MIN_LOOKAHEAD_BYTES, MAX_LOOKAHEAD_BYTES)
    };
    let max_read = MAX_ERROR_BODY_BYTES + lookahead + 1;
    let mut buf = Vec::new();
    let mut take_reader = (&mut reader).take(max_read as u64);
    if take_reader.read_to_end(&mut buf).is_err() {
        return "Failed to read response body".to_string();
    }
    let had_overflow = buf.len() == max_read;
    sanitize_error_bytes(&buf, token, had_overflow)
}

pub fn sanitize_error_bytes(bytes: &[u8], token: &str, stream_had_overflow: bool) -> String {
    if token.len() > MAX_LOOKAHEAD_BYTES {
        return OVERSIZED_TOKEN_SUPPRESSED_MSG.to_string();
    }
    if bytes.is_empty() {
        return "No response body from server".to_string();
    }

    // Convert valid UTF-8 portion of the entire read buffer (which contains lookahead)
    let valid_str = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            let valid_len = e.valid_up_to();
            std::str::from_utf8(&bytes[..valid_len]).unwrap_or_default()
        }
    };

    let trimmed = valid_str.trim();
    if trimmed.is_empty() {
        return "No response body from server".to_string();
    }

    // 1. Redact the active token on the whole buffer (includes lookahead to catch tokens crossing boundary)
    let mut sanitized = trimmed.to_string();
    if !token.is_empty() {
        sanitized = sanitized.replace(token, "<redacted>");
    }

    // 2. Redact any reflected Authorization field/header line. This intentionally
    // fails closed for JSON and other formats where punctuation may appear between
    // the field name and ':' (for example, `"Authorization":"Basic ..."`).
    let lines: Vec<String> = sanitized
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.contains("authorization") {
                "Authorization: <redacted>".to_string()
            } else {
                line.to_string()
            }
        })
        .collect();
    sanitized = lines.join("\n");

    // 3. Determine whether the response was truncated
    let is_truncated = stream_had_overflow
        || bytes.len() > MAX_ERROR_BODY_BYTES
        || sanitized.len() > MAX_ERROR_BODY_BYTES;

    if is_truncated {
        let mut cut_idx = MAX_ERROR_BODY_BYTES.min(sanitized.len());
        while cut_idx > 0 && !sanitized.is_char_boundary(cut_idx) {
            cut_idx -= 1;
        }

        // If truncation split the literal replacement "<redacted>", advance cut_idx to include it fully
        for prefix_len in 1.."<redacted>".len() {
            let prefix = &"<redacted>"[..prefix_len];
            if sanitized[..cut_idx].ends_with(prefix) {
                let suffix = &"<redacted>"[prefix_len..];
                if sanitized[cut_idx..].starts_with(suffix) {
                    cut_idx += suffix.len();
                    break;
                }
            }
        }

        // If truncation split "Authorization: <redacted>", advance cut_idx to include it fully
        let auth_redacted = "Authorization: <redacted>";
        for prefix_len in 1..auth_redacted.len() {
            let prefix = &auth_redacted[..prefix_len];
            if sanitized[..cut_idx].ends_with(prefix) {
                let suffix = &auth_redacted[prefix_len..];
                if sanitized[cut_idx..].starts_with(suffix) {
                    cut_idx += suffix.len();
                    break;
                }
            }
        }

        sanitized.truncate(cut_idx);
        sanitized.push_str(" ... [truncated]");
    }

    sanitized
}

pub fn sanitize_server_error(msg: &str, token: &str) -> String {
    sanitize_error_bytes(msg.as_bytes(), token, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_pacman_repo_url_formatting() {
        let url = pacman_repo_url("codeberg.org", "testuser", "x86-64-v3", "x86_64_v3");
        assert_eq!(
            url,
            "https://codeberg.org/api/packages/testuser/arch/x86-64-v3/x86_64_v3"
        );
    }

    #[test]
    fn test_insecure_http_rejected() {
        let client = CodebergClient::new().unwrap();
        let res = client.verify_token("http://codeberg.org", "testuser", "secret_token");
        assert!(
            matches!(res, Err(AppError::InsecureHttpRejected(url)) if url.starts_with("http://"))
        );

        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_file = temp_dir.path().join("pkg-1.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&pkg_file, b"data").unwrap();
        let res = client.upload_package(
            "http://codeberg.org",
            "testuser",
            "x86-64",
            "testuser",
            "secret_token",
            &pkg_file,
        );
        assert!(
            matches!(res, Err(AppError::InsecureHttpRejected(url)) if url.starts_with("http://"))
        );
    }

    #[test]
    fn test_production_http_client_enforces_https_transport() {
        let client = CodebergClient::new().unwrap();
        let err = client
            .client
            .get("http://127.0.0.1:1/transport-bypass")
            .send()
            .unwrap_err();
        assert!(err.is_builder(), "expected HTTPS-only builder error: {err}");
    }

    type MockInspectReceiver = std::sync::mpsc::Receiver<(String, Vec<String>)>;
    type MockServerResult = (String, MockInspectReceiver, thread::JoinHandle<()>);

    fn run_mock_server_inspect(status_line: &'static str, body: &'static str) -> MockServerResult {
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(&mut stream);
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line);
                let mut headers = Vec::new();
                let mut line = String::new();
                let mut content_len = 0;
                while let Ok(n) = reader.read_line(&mut line) {
                    if n == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                    if line.to_ascii_lowercase().starts_with("content-length:")
                        && let Some(val) = line.split(':').nth(1)
                    {
                        content_len = val.trim().parse::<usize>().unwrap_or(0);
                    }
                    headers.push(line.trim_end().to_string());
                    line.clear();
                }
                if content_len > 0 {
                    let mut body_buf = vec![0u8; content_len];
                    let _ = reader.read_exact(&mut body_buf);
                }
                let _ = tx.send((req_line.trim_end().to_string(), headers));

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status_line,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        (format!("http://127.0.0.1:{}", addr.port()), rx, handle)
    }

    // Helper to spin up a single-response mock HTTP server
    fn run_mock_server(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, thread::JoinHandle<()>) {
        let (host, _rx, handle) = run_mock_server_inspect(status_line, body);
        (host, handle)
    }

    #[test]
    fn test_codeberg_client_construction_success() {
        assert!(CodebergClient::new().is_ok());
        assert!(CodebergClient::new_test_client().is_ok());
    }

    #[test]
    fn test_http_client_init_error_display() {
        let err = AppError::HttpClientInit("builder error test".to_string());
        let displayed = format!("{err}");
        assert_eq!(
            displayed,
            "HTTP client initialization failed: builder error test"
        );
        assert!(!displayed.contains("secret"));
    }

    #[test]
    fn test_mock_token_verify_success() {
        let (host, rx, handle) = run_mock_server_inspect("200 OK", "[]");
        let client = CodebergClient::new_test_client().unwrap();
        let res = client.verify_token(&host, "testuser", "dummy_token");
        assert!(res.is_ok());
        let (req_line, headers) = rx.recv().unwrap();
        assert!(
            req_line.starts_with("GET /api/v1/packages/testuser?limit=1"),
            "Expected packages endpoint, got: {req_line}"
        );
        assert!(
            headers
                .iter()
                .any(|h| h.to_ascii_lowercase().starts_with("authorization: basic ")),
            "Expected HTTP Basic authorization header"
        );
        let _ = handle.join();
    }

    #[test]
    fn test_verify_token_package_capable_without_read_user_scope() {
        let (host, rx, handle) = run_mock_server_inspect("200 OK", "[]");
        let client = CodebergClient::new_test_client().unwrap();
        let res = client.verify_token(&host, "testuser", "scoped_or_unscoped_token");
        assert!(
            res.is_ok(),
            "Verification must succeed with package-capable credentials"
        );
        let (req_line, _) = rx.recv().unwrap();
        assert!(
            !req_line.contains("/api/v1/user"),
            "Must never request /api/v1/user: {req_line}"
        );
        assert!(
            req_line.contains("/api/v1/packages/testuser"),
            "Must target package registry: {req_line}"
        );
        let _ = handle.join();
    }

    #[test]
    fn test_mock_token_verify_owner_not_found() {
        let (host, handle) = run_mock_server("404 Not Found", r#"{"message":"user not found"}"#);
        let client = CodebergClient::new_test_client().unwrap();
        let res = client.verify_token(&host, "nonexistent_user", "dummy_token");
        assert!(matches!(res, Err(AppError::TokenVerificationFailed { .. })));
        let _ = handle.join();
    }

    #[test]
    fn test_mock_token_verify_unauthorized() {
        let (host, handle) =
            run_mock_server("401 Unauthorized", r#"{"message":"bad credentials"}"#);
        let client = CodebergClient::new_test_client().unwrap();
        let res = client.verify_token(&host, "testuser", "bad_token");
        assert!(matches!(res, Err(AppError::AuthenticationRejected)));
        let _ = handle.join();
    }

    #[test]
    fn test_mock_upload_success_201() {
        let (host, handle) = run_mock_server("201 Created", "Package uploaded");
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_file = temp_dir.path().join("pkg-1.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&pkg_file, b"fake package data").unwrap();

        let client = CodebergClient::new_test_client().unwrap();
        let res = client.upload_package(
            &host,
            "testuser",
            "x86-64",
            "testuser",
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

        let client = CodebergClient::new_test_client().unwrap();
        let res = client.upload_package(
            &host,
            "testuser",
            "x86-64",
            "testuser",
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
    fn test_mock_upload_server_error_500_with_redaction() {
        let (host, handle) = run_mock_server(
            "500 Internal Server Error",
            "Database error for token dummy_token_secret_123 with Authorization: Basic secret",
        );
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_file = temp_dir.path().join("pkg-1.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&pkg_file, b"fake package data").unwrap();

        let client = CodebergClient::new_test_client().unwrap();
        let res = client.upload_package(
            &host,
            "testuser",
            "x86-64",
            "testuser",
            "dummy_token_secret_123",
            &pkg_file,
        );
        assert!(
            matches!(res, Err(AppError::UploadFailed { ref message, .. }) if !message.contains("dummy_token_secret_123") && message.contains("<redacted>"))
        );
        let _ = handle.join();
    }

    #[test]
    fn test_mock_upload_streaming_large_file() {
        let (host, handle) = run_mock_server("201 Created", "Package uploaded");
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_file = temp_dir.path().join("big-1.0-1-x86_64.pkg.tar.zst");
        // 1MB payload to test streaming
        let payload = vec![0xABu8; 1024 * 1024];
        std::fs::write(&pkg_file, &payload).unwrap();

        let client = CodebergClient::new_test_client().unwrap();
        let res = client.upload_package(
            &host,
            "testuser",
            "x86-64",
            "testuser",
            "dummy_token",
            &pkg_file,
        );
        assert_eq!(res.unwrap(), UploadStatus::Success(201));
        let _ = handle.join();
    }

    #[test]
    fn test_sanitize_ascii_body_large() {
        let big_error = "E".repeat(2048);
        let sanitized = sanitize_server_error(&big_error, "tok");
        assert!(sanitized.len() <= MAX_ERROR_BODY_BYTES + 30);
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_sanitize_thai_utf8_crossing_boundary() {
        // "สวัสดีชาวโลก" is 36 UTF-8 bytes (12 chars * 3 bytes)
        let thai_unit = "สวัสดีชาวโลก";
        // Repeat to span across 1024 bytes
        let thai_string = thai_unit.repeat(100);
        assert!(thai_string.len() > 1024);

        // Must not panic on UTF-8 boundary!
        let sanitized = sanitize_server_error(&thai_string, "token123");
        assert!(sanitized.ends_with(" ... [truncated]"));
        // Assert that the entire string before truncation marker is valid UTF-8
        let text_part = sanitized.strip_suffix(" ... [truncated]").unwrap();
        assert!(!text_part.is_empty());
    }

    #[test]
    fn test_sanitize_emoji_crossing_boundary() {
        // Pad with ASCII so an emoji crosses offset 1024
        // 1022 'A's followed by 4-byte 🦀 (bytes [0xF0, 0x9F, 0xA6, 0x80])
        let mut bytes = vec![b'A'; 1022];
        bytes.extend_from_slice("🦀🚀✨".as_bytes());
        bytes.extend_from_slice(&[b'B'; 100]);

        // Must not panic and must safely back off the split emoji
        let sanitized = sanitize_error_bytes(&bytes, "my_token", false);
        assert!(sanitized.ends_with(" ... [truncated]"));
        let text_part = sanitized.strip_suffix(" ... [truncated]").unwrap();
        assert_eq!(text_part.len(), 1022);
        assert_eq!(text_part, &"A".repeat(1022));
    }

    #[test]
    fn test_sanitize_token_before_truncation() {
        let body_with_token = format!(
            "Error: token=secret_token_12345 and details: {}",
            "A".repeat(2000)
        );
        let sanitized = sanitize_server_error(&body_with_token, "secret_token_12345");
        assert!(!sanitized.contains("secret_token_12345"));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_sanitize_authorization_header_in_body() {
        let body = "Error 401\nAuthorization: Bearer secret_header_value\nDetail: unauthorized";
        let sanitized = sanitize_server_error(body, "other_token");
        assert!(!sanitized.contains("secret_header_value"));
        assert!(sanitized.contains("Authorization: <redacted>"));
    }

    #[test]
    fn test_sanitize_json_authorization_field() {
        let encoded_basic = "dGVzdHVzZXI6c2VjcmV0X3Rva2VuXzEyMw==";
        let body = format!(r#"{{"Authorization":"Basic {encoded_basic}"}}"#);
        let sanitized = sanitize_server_error(&body, "secret_token_123");
        assert!(!sanitized.contains(encoded_basic));
        assert_eq!(sanitized, "Authorization: <redacted>");
    }

    #[test]
    fn test_sanitize_json_authorization_near_truncation_boundary() {
        let encoded_basic = "dGVzdHVzZXI6c2VjcmV0X3Rva2VuXzEyMw==";
        let body = format!(
            r#"{}{{"Authorization":"Basic {encoded_basic}"}}"#,
            "A".repeat(MAX_ERROR_BODY_BYTES - 24)
        );
        let sanitized = read_and_sanitize_response(body.as_bytes(), "secret_token_123");
        assert!(!sanitized.contains(encoded_basic));
        assert!(sanitized.contains("Authorization: <redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_sanitize_empty_body() {
        let sanitized = sanitize_server_error("", "token");
        assert_eq!(sanitized, "No response body from server");

        let sanitized_spaces = sanitize_server_error("   \n\t  ", "token");
        assert_eq!(sanitized_spaces, "No response body from server");
    }

    #[test]
    fn test_bounded_reader_does_not_exhaust_infinite_stream() {
        // std::io::repeat is an infinite stream of 'X' bytes
        let infinite = std::io::repeat(b'X');
        let sanitized = read_and_sanitize_response(infinite, "my_token");
        assert!(sanitized.len() <= MAX_ERROR_BODY_BYTES + 30);
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_token_entirely_before_boundary() {
        let token = "SECRET_TOKEN_12345";
        let body = format!("{} {} {}", "A".repeat(100), token, "B".repeat(2000));
        let sanitized = read_and_sanitize_response(body.as_bytes(), token);
        assert!(!sanitized.contains(token));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_token_starts_exactly_at_boundary() {
        let token = "SECRET_TOKEN_12345";
        let body = format!("{}{}{}", "A".repeat(1024), token, "B".repeat(200));
        let sanitized = read_and_sanitize_response(body.as_bytes(), token);
        assert!(!sanitized.contains(token));
        assert!(!sanitized.contains("SECRET"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_token_begins_before_boundary_and_ends_after_boundary() {
        let token = "SECRET_TOKEN_12345";
        // Token starts at byte 1020, spans past 1024
        let body = format!("{}{}{}", "A".repeat(1020), token, "B".repeat(200));
        let sanitized = read_and_sanitize_response(body.as_bytes(), token);

        // Neither the full token nor the prefix "SECR" must appear
        assert!(!sanitized.contains(token));
        assert!(!sanitized.contains("SECR"));
        assert!(!sanitized.contains("SECRET"));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_only_1_byte_of_token_would_otherwise_be_visible_before_cutoff() {
        let token = "SECRET_TOKEN_12345";
        // Only 1 byte ('S') would land before 1024
        let body = format!("{}{}{}", "A".repeat(1023), token, "B".repeat(200));
        let sanitized = read_and_sanitize_response(body.as_bytes(), token);

        assert!(!sanitized.contains(token));
        assert!(!sanitized.contains("SECRET"));
        // Confirm no dangling 'S' at the cutoff
        let text_part = sanitized.strip_suffix(" ... [truncated]").unwrap();
        assert!(!text_part.ends_with('S'));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_multiple_token_occurrences() {
        let token = "SECRET_TOKEN_12345";
        let body = format!(
            "{}{}{}{}{}",
            token,
            "A".repeat(500),
            token,
            "B".repeat(510),
            token
        );
        let sanitized = read_and_sanitize_response(body.as_bytes(), token);
        assert!(!sanitized.contains(token));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_token_longer_than_diagnostic_limit() {
        // Token is ~1500 bytes, larger than visible diagnostic limit (1024)
        let token = format!("SECRET_LONG_{}_END", "X".repeat(1480));
        assert_eq!(token.len(), 1496);

        // Starts at offset 1000 in a 3000-byte stream
        let body = format!("{}{}{}", "A".repeat(1000), token, "B".repeat(1000));
        let sanitized = read_and_sanitize_response(body.as_bytes(), &token);

        assert!(!sanitized.contains(&token));
        assert!(!sanitized.contains("SECRET_LONG"));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.len() <= MAX_ERROR_BODY_BYTES + 30);
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_thai_adjacent_to_token_boundary() {
        let token = "SECRET_TOKEN_12345";
        // Thai characters (6 chars * 3 bytes = 18 bytes) immediately before boundary token
        let thai = "สวัสดี";
        // 1002 'A's + 18 bytes thai = 1020 bytes, so token starts at 1020 and crosses 1024
        let body = format!("{}{}{}{}", "A".repeat(1002), thai, token, "B".repeat(200));
        let sanitized = read_and_sanitize_response(body.as_bytes(), token);

        assert!(!sanitized.contains(token));
        assert!(!sanitized.contains("SECRET"));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_emoji_adjacent_to_token_boundary() {
        let token = "SECRET_TOKEN_12345";
        let emoji = "🦀🚀🔥";
        let body = format!("{}{}{}{}", "A".repeat(1010), emoji, token, "B".repeat(200));
        let sanitized = read_and_sanitize_response(body.as_bytes(), token);

        assert!(!sanitized.contains(token));
        assert!(!sanitized.contains("SECRET"));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_authorization_header_crossing_or_near_cutoff() {
        let auth_header = "Authorization: Bearer super_secret_access_token_67890";
        // Starts at offset 1010
        let body = format!("{}\n{}\n{}", "A".repeat(1010), auth_header, "B".repeat(300));
        let sanitized = read_and_sanitize_response(body.as_bytes(), "my_token");

        assert!(!sanitized.contains("super_secret_access_token_67890"));
        assert!(sanitized.contains("Authorization: <redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_oversized_token_length_equals_max_lookahead_bytes() {
        // Token length exactly at MAX_LOOKAHEAD_BYTES (65536)
        let token = "T".repeat(MAX_LOOKAHEAD_BYTES);
        assert_eq!(token.len(), MAX_LOOKAHEAD_BYTES);

        // Starts at offset 1000 in a stream, crossing diagnostic boundary 1024
        let body = format!("{}{}{}", "A".repeat(1000), token, "B".repeat(100));
        let sanitized = read_and_sanitize_response(body.as_bytes(), &token);

        // Within lookahead window: properly redacted, NOT completely suppressed
        assert_ne!(sanitized, OVERSIZED_TOKEN_SUPPRESSED_MSG);
        assert!(!sanitized.contains(&token));
        assert!(sanitized.contains("<redacted>"));
        assert!(sanitized.ends_with(" ... [truncated]"));
    }

    #[test]
    fn test_oversized_token_length_equals_max_lookahead_plus_one() {
        // Token length exactly MAX_LOOKAHEAD_BYTES + 1 (65537)
        let token = format!("SECRET_PREFIX_{}", "Z".repeat(MAX_LOOKAHEAD_BYTES - 13));
        assert_eq!(token.len(), MAX_LOOKAHEAD_BYTES + 1);

        let body = format!(
            "Database error: query timed out. Extra info: {} ... please retry",
            token
        );
        let sanitized = read_and_sanitize_response(body.as_bytes(), &token);

        // Response body content must be completely suppressed
        assert_eq!(sanitized, OVERSIZED_TOKEN_SUPPRESSED_MSG);
        assert!(!sanitized.contains("Database error"));
        assert!(!sanitized.contains("please retry"));
        // No token bytes or token prefix must be present
        assert!(!sanitized.contains(&token));
        assert!(!sanitized.contains("SECRET_PREFIX"));
        assert!(!sanitized.contains('Z'));
    }

    #[test]
    fn test_oversized_token_very_large() {
        // Very large token (e.g. 200,000 bytes)
        let token = format!("VERY_LARGE_TOKEN_{}", "K".repeat(200_000));
        let body = format!("Server failure details: {token}");

        let sanitized = read_and_sanitize_response(body.as_bytes(), &token);
        assert_eq!(sanitized, OVERSIZED_TOKEN_SUPPRESSED_MSG);
        assert!(!sanitized.contains("Server failure details"));
        assert!(!sanitized.contains(&token));
        assert!(!sanitized.contains("VERY_LARGE_TOKEN"));
        assert!(!sanitized.contains('K'));
    }

    #[test]
    fn test_oversized_token_begins_before_byte_1024() {
        let token = format!("TOKEN_EARLY_{}", "X".repeat(MAX_LOOKAHEAD_BYTES));
        assert_eq!(token.len(), MAX_LOOKAHEAD_BYTES + 12);

        // Token begins at byte 500 (before 1024), body has useful text before and after
        let body = format!(
            "{}{}{}",
            "Error line 1: failed auth. ".repeat(15),
            token,
            " extra"
        );
        let sanitized = read_and_sanitize_response(body.as_bytes(), &token);

        assert_eq!(sanitized, OVERSIZED_TOKEN_SUPPRESSED_MSG);
        assert!(!sanitized.contains("Error line 1"));
        assert!(!sanitized.contains("TOKEN_EARLY"));
        assert!(!sanitized.contains('X'));
    }

    #[test]
    fn test_oversized_token_starts_exactly_around_diagnostic_boundary() {
        let token = format!("BOUNDARY_TOKEN_{}", "Y".repeat(MAX_LOOKAHEAD_BYTES));
        assert_eq!(token.len(), MAX_LOOKAHEAD_BYTES + 15);

        // Starts exactly at byte 1024
        let body_at_boundary = format!("{}{}", "A".repeat(1024), token);
        let sanitized = read_and_sanitize_response(body_at_boundary.as_bytes(), &token);
        assert_eq!(sanitized, OVERSIZED_TOKEN_SUPPRESSED_MSG);
        assert!(!sanitized.contains('A'));
        assert!(!sanitized.contains("BOUNDARY_TOKEN"));

        // Starts at byte 1020 (spans across 1024)
        let body_crossing = format!("{}{}{}", "B".repeat(1020), token, "C".repeat(50));
        let sanitized_cross = read_and_sanitize_response(body_crossing.as_bytes(), &token);
        assert_eq!(sanitized_cross, OVERSIZED_TOKEN_SUPPRESSED_MSG);
        assert!(!sanitized_cross.contains('B'));
        assert!(!sanitized_cross.contains("BOUNDARY_TOKEN"));
    }

    #[test]
    fn test_oversized_token_with_infinite_stream() {
        let token = "T".repeat(MAX_LOOKAHEAD_BYTES + 10);
        let infinite = std::io::repeat(b'W');

        // Bounded memory / execution, does not loop or exhaust memory
        let sanitized = read_and_sanitize_response(infinite, &token);
        assert_eq!(sanitized, OVERSIZED_TOKEN_SUPPRESSED_MSG);
        assert!(!sanitized.contains('W'));
    }
}
