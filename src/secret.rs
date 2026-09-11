use crate::error::AppError;
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const APP_ID: &str = "cbpkg";
pub const ITEM_LABEL: &str = "cbpkg Codeberg token";

#[derive(PartialEq, Eq)]
pub struct SecretCredential {
    pub username: String,
    pub token: String,
}

impl Drop for SecretCredential {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl fmt::Debug for SecretCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretCredential")
            .field("username", &self.username)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialState {
    Missing,
    Present { username: String },
    Duplicate { count: usize },
}

pub fn normalize_host(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::InputError("Host cannot be empty".to_string()));
    }

    let url_str = if let Some(idx) = trimmed.find("://") {
        let scheme = &trimmed[..idx];
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(AppError::InputError(format!(
                "Unsupported URL scheme in host: '{raw}'"
            )));
        }
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };

    let url = reqwest::Url::parse(&url_str)
        .map_err(|e| AppError::InputError(format!("Invalid host or URL '{raw}': {e}")))?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::InputError(format!(
            "Host cannot contain user credentials: '{raw}'"
        )));
    }

    if url.query().is_some() {
        return Err(AppError::InputError(format!(
            "Host cannot contain query string: '{raw}'"
        )));
    }

    if url.fragment().is_some() {
        return Err(AppError::InputError(format!(
            "Host cannot contain fragment: '{raw}'"
        )));
    }

    let path = url.path();
    if !path.is_empty() && path != "/" {
        return Err(AppError::InputError(format!(
            "Host cannot contain a non-root path: '{raw}'"
        )));
    }

    let raw_host = url
        .host_str()
        .ok_or_else(|| AppError::InputError(format!("Missing host in '{raw}'")))?;

    let clean_host = raw_host.trim_end_matches('.');
    if clean_host.is_empty() {
        return Err(AppError::InputError(format!("Invalid host: '{raw}'")));
    }
    let lower_host = clean_host.to_ascii_lowercase();

    let port = match (url.scheme(), url.port()) {
        ("http", Some(80)) => None,
        ("https", Some(443)) => None,
        (_, port) => port,
    };

    let canonical = if let Some(p) = port {
        format!("{lower_host}:{p}")
    } else {
        lower_host
    };

    Ok(canonical)
}

pub trait CredentialStore: Send + Sync {
    fn lookup_credential(&self, host: &str) -> Result<CredentialState, AppError>;
    fn load_credential(&self, host: &str) -> Result<SecretCredential, AppError>;
    fn store_credential(&self, host: &str, username: &str, token: &str) -> Result<(), AppError>;
    fn delete_credential(&self, host: &str) -> Result<bool, AppError>;
}

#[cfg(unix)]
pub(crate) fn validate_runtime_dir(dir: &Path, expected_uid: u32) -> Result<bool, AppError> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };

    // Must be a directory and not a symlink
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Ok(false);
    }

    // Must be owned by the expected UID
    if meta.uid() != expected_uid {
        return Ok(false);
    }

    // Must not be writable by group or others (0o022 mask must be 0)
    let permissions_mode = meta.mode() & 0o777;
    if (permissions_mode & 0o022) != 0 {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(unix)]
pub(crate) fn resolve_secure_runtime_dir() -> Result<PathBuf, AppError> {
    let uid = unsafe { libc::getuid() };

    // 1. Check $XDG_RUNTIME_DIR if suitable
    if let Some(xdg_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(xdg_dir);
        if !path.as_os_str().is_empty() && validate_runtime_dir(&path, uid)? {
            return Ok(path);
        }
    }

    // 2. Check /run/user/<uid>
    let fallback = PathBuf::from(format!("/run/user/{uid}"));
    if validate_runtime_dir(&fallback, uid)? {
        return Ok(fallback);
    }

    Err(AppError::SecretService(format!(
        "No secure per-user runtime directory available for UID {uid} ($XDG_RUNTIME_DIR or /run/user/{uid}). Insecure fallback rejected."
    )))
}

#[cfg(unix)]
pub struct CredentialLock {
    file: std::fs::File,
}

#[cfg(unix)]
impl CredentialLock {
    pub fn acquire() -> Result<Self, AppError> {
        let runtime_dir = resolve_secure_runtime_dir()?;
        Self::acquire_in_dir(&runtime_dir)
    }

    pub(crate) fn acquire_in_dir(dir: &Path) -> Result<Self, AppError> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let uid = unsafe { libc::getuid() };
        if !validate_runtime_dir(dir, uid)? {
            return Err(AppError::SecretService(format!(
                "Directory {} is not a secure runtime directory for UID {uid}",
                dir.display()
            )));
        }

        let lock_path = dir.join(format!("cbpkg-cred-{uid}.lock"));

        let c_path = CString::new(lock_path.as_os_str().as_bytes())
            .map_err(|e| AppError::SecretService(format!("Invalid lock path: {e}")))?;

        let flags = libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let mode: libc::mode_t = 0o600;

        let fd = unsafe { libc::open(c_path.as_ptr(), flags, mode) };
        if fd < 0 {
            return Err(AppError::SecretService(format!(
                "Failed opening credential lock at {}: {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            )));
        }

        let file = unsafe { std::fs::File::from_raw_fd(fd) };

        // Verify the opened file descriptor via fstat
        let meta = file.metadata().map_err(|e| {
            AppError::SecretService(format!("Failed to stat lock file descriptor: {e}"))
        })?;

        if !meta.is_file() {
            return Err(AppError::SecretService(format!(
                "Lock path {} is not a regular file",
                lock_path.display()
            )));
        }

        if meta.uid() != uid {
            return Err(AppError::SecretService(format!(
                "Lock file {} is owned by UID {}, expected UID {uid}",
                lock_path.display(),
                meta.uid()
            )));
        }

        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(AppError::SecretService(format!(
                "Failed acquiring credential lock: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for CredentialLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub struct SecretServiceStore;

impl SecretServiceStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SecretServiceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore for SecretServiceStore {
    fn lookup_credential(&self, host: &str) -> Result<CredentialState, AppError> {
        let host = normalize_host(host)?;

        let ss = SecretService::connect(EncryptionType::Dh)
            .map_err(|e| AppError::SecretService(e.to_string()))?;

        let collection = ss.get_default_collection().map_err(|e| {
            AppError::SecretService(format!("Failed to get default collection: {e}"))
        })?;

        collection
            .ensure_unlocked()
            .map_err(|_| AppError::CollectionLocked)?;

        let mut search_attrs = HashMap::new();
        search_attrs.insert("application", APP_ID);
        search_attrs.insert("host", &host);

        let items = collection
            .search_items(search_attrs)
            .map_err(|e| AppError::SecretService(format!("Search items failed: {e}")))?;

        match items.len() {
            0 => Ok(CredentialState::Missing),
            1 => {
                let item = &items[0];
                let attrs = item.get_attributes().map_err(|e| {
                    AppError::SecretService(format!("Failed to get item attributes: {e}"))
                })?;

                let username = match attrs.get("username") {
                    Some(u) if !u.trim().is_empty() => u.clone(),
                    _ => return Err(AppError::MalformedCredential(host)),
                };

                // Metadata only: never retrieve secret payload here
                Ok(CredentialState::Present { username })
            }
            count => Ok(CredentialState::Duplicate { count }),
        }
    }

    fn load_credential(&self, host: &str) -> Result<SecretCredential, AppError> {
        let host = normalize_host(host)?;

        let ss = SecretService::connect(EncryptionType::Dh)
            .map_err(|e| AppError::SecretService(e.to_string()))?;

        let collection = ss.get_default_collection().map_err(|e| {
            AppError::SecretService(format!("Failed to get default collection: {e}"))
        })?;

        collection
            .ensure_unlocked()
            .map_err(|_| AppError::CollectionLocked)?;

        let mut search_attrs = HashMap::new();
        search_attrs.insert("application", APP_ID);
        search_attrs.insert("host", &host);

        let items = collection
            .search_items(search_attrs)
            .map_err(|e| AppError::SecretService(format!("Search items failed: {e}")))?;

        match items.len() {
            0 => Err(AppError::CredentialMissing(host)),
            1 => {
                let item = &items[0];
                let attrs = item.get_attributes().map_err(|e| {
                    AppError::SecretService(format!("Failed to get item attributes: {e}"))
                })?;

                let username = match attrs.get("username") {
                    Some(u) if !u.trim().is_empty() => u.clone(),
                    _ => return Err(AppError::MalformedCredential(host)),
                };

                // Sole Secret Service method authorized to retrieve token payload
                let secret_bytes = item.get_secret().map_err(|e| {
                    AppError::SecretService(format!("Failed to read secret payload: {e}"))
                })?;

                let token = String::from_utf8(secret_bytes).map_err(|e| {
                    AppError::SecretService(format!("Secret is not valid UTF-8: {e}"))
                })?;

                Ok(SecretCredential { username, token })
            }
            _ => Err(AppError::DuplicateCredentials(host)),
        }
    }

    fn store_credential(&self, host: &str, username: &str, token: &str) -> Result<(), AppError> {
        let _lock = CredentialLock::acquire()?;
        let host = normalize_host(host)?;

        let ss = SecretService::connect(EncryptionType::Dh)
            .map_err(|e| AppError::SecretService(e.to_string()))?;

        let collection = ss.get_default_collection().map_err(|e| {
            AppError::SecretService(format!("Failed to get default collection: {e}"))
        })?;

        collection
            .ensure_unlocked()
            .map_err(|_| AppError::CollectionLocked)?;

        // Search for existing cbpkg credentials and strictly enforce single-account invariant
        let mut search_attrs = HashMap::new();
        search_attrs.insert("application", APP_ID);
        search_attrs.insert("host", &host);

        let existing_items = collection
            .search_items(search_attrs)
            .map_err(|e| AppError::SecretService(format!("Search existing items failed: {e}")))?;

        match existing_items.len() {
            0 => {}
            1 => {
                let attrs = existing_items[0].get_attributes().map_err(|e| {
                    AppError::SecretService(format!(
                        "Failed to get existing credential attributes: {e}"
                    ))
                })?;
                let existing_user = match attrs.get("username") {
                    Some(u) if !u.trim().is_empty() => u.clone(),
                    _ => return Err(AppError::MalformedCredential(host)),
                };
                return Err(AppError::CredentialAlreadyExists {
                    host,
                    username: existing_user,
                });
            }
            _ => return Err(AppError::DuplicateCredentials(host)),
        }

        let mut attrs = HashMap::new();
        attrs.insert("application", APP_ID);
        attrs.insert("host", &host);
        attrs.insert("username", username);

        collection
            .create_item(ITEM_LABEL, attrs, token.as_bytes(), false, "text/plain")
            .map_err(|e| AppError::SecretService(format!("Failed to create secret item: {e}")))?;

        Ok(())
    }

    fn delete_credential(&self, host: &str) -> Result<bool, AppError> {
        let _lock = CredentialLock::acquire()?;
        let host = normalize_host(host)?;

        let ss = SecretService::connect(EncryptionType::Dh)
            .map_err(|e| AppError::SecretService(e.to_string()))?;

        let collection = ss.get_default_collection().map_err(|e| {
            AppError::SecretService(format!("Failed to get default collection: {e}"))
        })?;

        collection
            .ensure_unlocked()
            .map_err(|_| AppError::CollectionLocked)?;

        let mut search_attrs = HashMap::new();
        search_attrs.insert("application", APP_ID);
        search_attrs.insert("host", &host);

        let items = collection
            .search_items(search_attrs)
            .map_err(|e| AppError::SecretService(format!("Search items failed: {e}")))?;

        if items.is_empty() {
            return Ok(false);
        }

        for item in items {
            item.delete()
                .map_err(|e| AppError::SecretService(format!("Failed to delete item: {e}")))?;
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    pub struct MockCredentialStore {
        pub items: std::sync::Mutex<Vec<(String, String, String, String)>>,
        pub lookup_count: AtomicUsize,
        pub load_count: AtomicUsize,
        pub fail_search: AtomicBool,
        pub fail_attributes: AtomicBool,
        pub fail_delete: AtomicBool,
    }

    impl MockCredentialStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl CredentialStore for MockCredentialStore {
        fn lookup_credential(&self, host: &str) -> Result<CredentialState, AppError> {
            self.lookup_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_search.load(Ordering::SeqCst) {
                return Err(AppError::SecretService(
                    "Simulated search error".to_string(),
                ));
            }
            let host = normalize_host(host)?;
            let items = self.items.lock().unwrap();
            let matching: Vec<_> = items
                .iter()
                .filter(|(app, h, _, _)| app == APP_ID && h == &host)
                .collect();

            match matching.len() {
                0 => Ok(CredentialState::Missing),
                1 => {
                    if self.fail_attributes.load(Ordering::SeqCst) {
                        return Err(AppError::SecretService(
                            "Simulated attribute error".to_string(),
                        ));
                    }
                    if matching[0].2.trim().is_empty() {
                        return Err(AppError::MalformedCredential(host));
                    }
                    Ok(CredentialState::Present {
                        username: matching[0].2.clone(),
                    })
                }
                count => Ok(CredentialState::Duplicate { count }),
            }
        }

        fn load_credential(&self, host: &str) -> Result<SecretCredential, AppError> {
            self.load_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_search.load(Ordering::SeqCst) {
                return Err(AppError::SecretService(
                    "Simulated search error".to_string(),
                ));
            }
            let host = normalize_host(host)?;
            let items = self.items.lock().unwrap();
            let matching: Vec<_> = items
                .iter()
                .filter(|(app, h, _, _)| app == APP_ID && h == &host)
                .collect();

            match matching.len() {
                0 => Err(AppError::CredentialMissing(host)),
                1 => {
                    if self.fail_attributes.load(Ordering::SeqCst) {
                        return Err(AppError::SecretService(
                            "Simulated attribute error".to_string(),
                        ));
                    }
                    if matching[0].2.trim().is_empty() {
                        return Err(AppError::MalformedCredential(host));
                    }
                    Ok(SecretCredential {
                        username: matching[0].2.clone(),
                        token: matching[0].3.clone(),
                    })
                }
                _ => Err(AppError::DuplicateCredentials(host)),
            }
        }

        fn store_credential(
            &self,
            host: &str,
            username: &str,
            token: &str,
        ) -> Result<(), AppError> {
            if self.fail_search.load(Ordering::SeqCst) {
                return Err(AppError::SecretService(
                    "Simulated search error".to_string(),
                ));
            }
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(AppError::SecretService(
                    "Simulated delete error".to_string(),
                ));
            }

            let host = normalize_host(host)?;
            let mut items = self.items.lock().unwrap();
            let matching: Vec<_> = items
                .iter()
                .filter(|(app, h, _, _)| app == APP_ID && h == &host)
                .collect();

            match matching.len() {
                0 => {}
                1 => {
                    if self.fail_attributes.load(Ordering::SeqCst) {
                        return Err(AppError::SecretService(
                            "Simulated attribute error".to_string(),
                        ));
                    }
                    let existing_user = &matching[0].2;
                    if existing_user.trim().is_empty() {
                        return Err(AppError::MalformedCredential(host));
                    }
                    return Err(AppError::CredentialAlreadyExists {
                        host,
                        username: existing_user.clone(),
                    });
                }
                _ => return Err(AppError::DuplicateCredentials(host)),
            }

            items.push((
                APP_ID.to_string(),
                host,
                username.to_string(),
                token.to_string(),
            ));
            Ok(())
        }

        fn delete_credential(&self, host: &str) -> Result<bool, AppError> {
            if self.fail_search.load(Ordering::SeqCst) {
                return Err(AppError::SecretService(
                    "Simulated search error".to_string(),
                ));
            }
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(AppError::SecretService(
                    "Simulated delete error".to_string(),
                ));
            }

            let host = normalize_host(host)?;
            let mut items = self.items.lock().unwrap();
            let before = items.len();
            items.retain(|(app, h, _, _)| !(app == APP_ID && h == &host));
            Ok(items.len() < before)
        }
    }

    #[test]
    fn test_secret_credential_debug_redacted() {
        let cred = SecretCredential {
            username: "testuser".to_string(),
            token: "secret_token_12345".to_string(),
        };
        let debug_str = format!("{cred:?}");
        assert!(!debug_str.contains("secret_token_12345"));
        assert!(debug_str.contains("<redacted>"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_secret_token_zeroize_clears_buffer() {
        let mut cred = SecretCredential {
            username: "testuser".to_string(),
            token: "super_secret_token_to_zeroize".to_string(),
        };
        assert_eq!(cred.token.len(), 29);
        cred.token.zeroize();
        assert!(cred.token.is_empty());
    }

    #[test]
    fn test_entered_login_token_zeroizing_wrapper() {
        use zeroize::Zeroizing;
        let mut token = Zeroizing::new("my_interactive_entered_token_123".to_string());
        assert_eq!(token.trim(), "my_interactive_entered_token_123");
        // Safe verification while allocation is still alive
        token.zeroize();
        assert!(token.is_empty());
    }

    #[test]
    fn test_secret_credential_drop_zeroizes_structurally() {
        let cred = SecretCredential {
            username: "testuser".to_string(),
            token: "active_token_123".to_string(),
        };
        assert_eq!(cred.token, "active_token_123");
        // Drop implementation calls self.token.zeroize()
        drop(cred);
    }

    #[test]
    fn test_metadata_vs_secret_access_login_precheck() {
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "testuser", "token_abc")
            .unwrap();

        // Login precheck performs metadata lookup only
        let state = store.lookup_credential("codeberg.org").unwrap();
        assert_eq!(
            state,
            CredentialState::Present {
                username: "testuser".to_string()
            }
        );
        assert_eq!(store.lookup_count.load(Ordering::SeqCst), 1);
        // CRITICAL: secret token was never accessed
        assert_eq!(store.load_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_metadata_vs_secret_access_status() {
        let store = MockCredentialStore::new();

        // Status on Missing host
        let state_missing = store.lookup_credential("codeberg.org").unwrap();
        assert_eq!(state_missing, CredentialState::Missing);
        assert_eq!(store.lookup_count.load(Ordering::SeqCst), 1);
        assert_eq!(store.load_count.load(Ordering::SeqCst), 0);

        // Status on Present host
        store
            .store_credential("codeberg.org", "testuser", "token_xyz")
            .unwrap();
        let state_present = store.lookup_credential("codeberg.org").unwrap();
        assert_eq!(
            state_present,
            CredentialState::Present {
                username: "testuser".to_string()
            }
        );
        assert_eq!(store.lookup_count.load(Ordering::SeqCst), 2);
        // CRITICAL: secret token was never accessed
        assert_eq!(store.load_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_load_credential_loads_secret_and_tracks_count() {
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "testuser", "token_secret_only")
            .unwrap();

        let cred = store.load_credential("codeberg.org").unwrap();
        assert_eq!(cred.username, "testuser");
        assert_eq!(cred.token, "token_secret_only");
        assert_eq!(store.load_count.load(Ordering::SeqCst), 1);
        assert_eq!(store.lookup_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_load_credential_errors_on_missing_and_duplicate() {
        let store = MockCredentialStore::new();
        let err_missing = store.load_credential("codeberg.org");
        assert!(matches!(err_missing, Err(AppError::CredentialMissing(h)) if h == "codeberg.org"));

        // Inject duplicate legacy items
        {
            let mut items = store.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "user1".to_string(),
                "tok1".to_string(),
            ));
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "user2".to_string(),
                "tok2".to_string(),
            ));
        }

        let err_dup = store.load_credential("codeberg.org");
        assert!(matches!(err_dup, Err(AppError::DuplicateCredentials(h)) if h == "codeberg.org"));
    }

    #[test]
    fn test_malformed_credential_missing_username() {
        let store = MockCredentialStore::new();
        {
            let mut items = store.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "".to_string(), // empty username
                "tok1".to_string(),
            ));
        }

        let res_lookup = store.lookup_credential("codeberg.org");
        assert!(matches!(res_lookup, Err(AppError::MalformedCredential(h)) if h == "codeberg.org"));

        let res_load = store.load_credential("codeberg.org");
        assert!(matches!(res_load, Err(AppError::MalformedCredential(h)) if h == "codeberg.org"));
    }

    #[test]
    fn test_login_with_no_existing_credential_succeeds() {
        let store = MockCredentialStore::new();
        assert_eq!(
            store.lookup_credential("codeberg.org").unwrap(),
            CredentialState::Missing
        );
        store
            .store_credential("codeberg.org", "testuser", "token_a")
            .unwrap();
        assert_eq!(
            store.lookup_credential("codeberg.org").unwrap(),
            CredentialState::Present {
                username: "testuser".to_string()
            }
        );
    }

    #[test]
    fn test_login_refuses_when_same_username_already_exists() {
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "testuser", "token_a")
            .unwrap();

        let res = store.store_credential("codeberg.org", "testuser", "token_b");
        assert!(matches!(
            res,
            Err(AppError::CredentialAlreadyExists { host, username })
                if host == "codeberg.org" && username == "testuser"
        ));

        // Original credential is not modified
        let cred = store.load_credential("codeberg.org").unwrap();
        assert_eq!(cred.token, "token_a");
    }

    #[test]
    fn test_login_refuses_when_different_username_already_exists() {
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "testuser", "token_a")
            .unwrap();

        let res = store.store_credential("codeberg.org", "other_user", "token_b");
        assert!(matches!(
            res,
            Err(AppError::CredentialAlreadyExists { host, username })
                if host == "codeberg.org" && username == "testuser"
        ));

        // Original credential is not modified
        let cred = store.load_credential("codeberg.org").unwrap();
        assert_eq!(cred.token, "token_a");
    }

    #[test]
    fn test_logout_clears_credential_and_is_idempotent() {
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "testuser", "token_a")
            .unwrap();

        // Logout clears credential and returns true
        assert!(store.delete_credential("codeberg.org").unwrap());
        assert_eq!(
            store.lookup_credential("codeberg.org").unwrap(),
            CredentialState::Missing
        );

        // Subsequent logout on empty store succeeds/idempotent and returns false
        assert!(!store.delete_credential("codeberg.org").unwrap());

        // Can log in again after logout
        store
            .store_credential("codeberg.org", "new_user", "token_new")
            .unwrap();
        assert_eq!(
            store.lookup_credential("codeberg.org").unwrap(),
            CredentialState::Present {
                username: "new_user".to_string()
            }
        );
    }

    #[test]
    fn test_status_and_lookup_with_duplicate_legacy_items() {
        let store = MockCredentialStore::new();
        {
            let mut items = store.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "testuser".to_string(),
                "old_token_1".to_string(),
            ));
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "testuser_alt".to_string(),
                "old_token_2".to_string(),
            ));
        }

        // Lookup detects duplicates and does not pick first item
        assert_eq!(
            store.lookup_credential("codeberg.org").unwrap(),
            CredentialState::Duplicate { count: 2 }
        );

        // Store attempt on duplicate items fails with DuplicateCredentials
        let res = store.store_credential("codeberg.org", "testuser", "token_3");
        assert!(matches!(
            res,
            Err(AppError::DuplicateCredentials(host)) if host == "codeberg.org"
        ));

        // Logout cleans all duplicate legacy items
        assert!(store.delete_credential("codeberg.org").unwrap());
        assert_eq!(
            store.lookup_credential("codeberg.org").unwrap(),
            CredentialState::Missing
        );
        assert!(store.items.lock().unwrap().is_empty());
    }

    #[test]
    fn test_build_upload_lookup_never_picks_first_item_on_duplicate() {
        let store = MockCredentialStore::new();
        {
            let mut items = store.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "user1".to_string(),
                "tok1".to_string(),
            ));
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "user2".to_string(),
                "tok2".to_string(),
            ));
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "user3".to_string(),
                "tok3".to_string(),
            ));
        }

        let lookup = store.lookup_credential("codeberg.org").unwrap();
        // Crucial invariant: never pick first item arbitrarily
        assert_eq!(lookup, CredentialState::Duplicate { count: 3 });
    }

    #[test]
    fn test_table_driven_host_normalization_accepted() {
        let accepted = vec![
            ("codeberg.org", "codeberg.org"),
            ("CODEBERG.ORG", "codeberg.org"),
            ("  codeberg.org  ", "codeberg.org"),
            ("https://codeberg.org", "codeberg.org"),
            ("https://codeberg.org/", "codeberg.org"),
            ("http://codeberg.org", "codeberg.org"),
            ("http://codeberg.org/", "codeberg.org"),
            ("codeberg.org.", "codeberg.org"),
            ("https://codeberg.org.", "codeberg.org"),
            ("https://codeberg.org:443", "codeberg.org"),
            ("https://codeberg.org:443/", "codeberg.org"),
            ("http://codeberg.org:80", "codeberg.org"),
            ("http://codeberg.org:80/", "codeberg.org"),
            ("codeberg.org:443", "codeberg.org"),
            ("codeberg.org:80", "codeberg.org:80"),
            ("https://codeberg.org:80", "codeberg.org:80"),
            ("http://codeberg.org:443", "codeberg.org:443"),
            ("https://example.org:8443", "example.org:8443"),
            ("example.org:8443", "example.org:8443"),
            ("http://example.org:8080", "example.org:8080"),
            ("https://codeberg.example:8443", "codeberg.example:8443"),
            ("codeberg.example:8443", "codeberg.example:8443"),
            ("https://[2001:db8::1]:8443", "[2001:db8::1]:8443"),
            ("[2001:db8::1]:8443", "[2001:db8::1]:8443"),
            ("https://[2001:db8::1]:443", "[2001:db8::1]"),
            ("http://[2001:db8::1]:80", "[2001:db8::1]"),
            ("http://[2001:db8::1]:443", "[2001:db8::1]:443"),
            ("[::1]", "[::1]"),
        ];

        for (input, expected) in accepted {
            let result = normalize_host(input)
                .unwrap_or_else(|e| panic!("Failed to normalize valid input '{input}': {e}"));
            assert_eq!(result, expected, "Mismatch for input: '{input}'");
        }
    }

    #[test]
    fn test_table_driven_host_normalization_rejected() {
        let rejected = vec![
            "",
            "   ",
            "https://",
            "https://user@codeberg.org",
            "https://user:password@codeberg.org",
            "user@codeberg.org",
            "user:password@codeberg.org",
            "https://codeberg.org/foo",
            "https://codeberg.org/api",
            "codeberg.org/path",
            "https://codeberg.org//",
            "https://codeberg.org?query",
            "codeberg.org?query",
            "https://codeberg.org#fragment",
            "codeberg.org#fragment",
            "ftp://codeberg.org",
            "ssh://codeberg.org",
            "file:///codeberg.org",
            "codeberg.org:99999",
            "codeberg.org:invalid",
        ];

        for input in rejected {
            assert!(
                normalize_host(input).is_err(),
                "Expected input '{input}' to be rejected"
            );
        }
    }

    #[test]
    fn test_accepted_host_variants_hit_same_credential_store_key() {
        let store = MockCredentialStore::new();

        // Stored with URL format
        store
            .store_credential("https://codeberg.org/", "testuser", "token_x")
            .unwrap();

        let variants = vec![
            "codeberg.org",
            "CODEBERG.ORG",
            "  codeberg.org  ",
            "https://codeberg.org",
            "https://codeberg.org:443",
            "http://codeberg.org:80/",
            "codeberg.org.",
        ];

        for variant in variants {
            assert_eq!(
                store.lookup_credential(variant).unwrap(),
                CredentialState::Present {
                    username: "testuser".to_string()
                },
                "Lookup failed for equivalent variant '{variant}'"
            );

            // Storing with variant is refused because credential already exists
            let res = store.store_credential(variant, "testuser", "token_dup");
            assert!(
                matches!(res, Err(AppError::CredentialAlreadyExists { .. })),
                "Expected duplicate refusal for variant '{variant}'"
            );
        }

        // Logout using bare host cleans it for all variants
        assert!(store.delete_credential("codeberg.org").unwrap());
        assert_eq!(
            store.lookup_credential("https://codeberg.org").unwrap(),
            CredentialState::Missing
        );
    }

    #[test]
    fn test_different_hosts_remain_isolated() {
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "user_codeberg", "tok_cb")
            .unwrap();
        store
            .store_credential("gitlab.com", "user_gitlab", "tok_gl")
            .unwrap();

        // Logout from codeberg.org only
        assert!(store.delete_credential("codeberg.org").unwrap());

        assert_eq!(
            store.lookup_credential("codeberg.org").unwrap(),
            CredentialState::Missing
        );
        assert_eq!(
            store.lookup_credential("gitlab.com").unwrap(),
            CredentialState::Present {
                username: "user_gitlab".to_string()
            }
        );
    }

    #[test]
    fn test_other_app_isolated() {
        let store = MockCredentialStore::new();
        {
            let mut items = store.items.lock().unwrap();
            items.push((
                "other_app".to_string(),
                "codeberg.org".to_string(),
                "user_other".to_string(),
                "token_other".to_string(),
            ));
        }

        // cbpkg should see Missing for codeberg.org
        assert_eq!(
            store.lookup_credential("codeberg.org").unwrap(),
            CredentialState::Missing
        );

        // Storing cbpkg credential works without touching other_app
        store
            .store_credential("codeberg.org", "testuser", "cb_tok")
            .unwrap();

        // Logout from codeberg.org removes cbpkg credential but keeps other_app
        assert!(store.delete_credential("codeberg.org").unwrap());
        let items = store.items.lock().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "other_app");
    }

    #[test]
    fn test_search_failure_propagation() {
        let store = MockCredentialStore::new();
        store.fail_search.store(true, Ordering::SeqCst);

        let res = store.store_credential("codeberg.org", "testuser", "token_a");
        assert!(matches!(res, Err(AppError::SecretService(msg)) if msg.contains("search error")));
        assert!(store.items.lock().unwrap().is_empty());

        let res_lookup = store.lookup_credential("codeberg.org");
        assert!(
            matches!(res_lookup, Err(AppError::SecretService(msg)) if msg.contains("search error"))
        );

        let res_load = store.load_credential("codeberg.org");
        assert!(
            matches!(res_load, Err(AppError::SecretService(msg)) if msg.contains("search error"))
        );
    }

    #[test]
    fn test_delete_failure_propagation() {
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "testuser", "token_a")
            .unwrap();

        store.fail_delete.store(true, Ordering::SeqCst);

        let res = store.delete_credential("codeberg.org");
        assert!(matches!(res, Err(AppError::SecretService(msg)) if msg.contains("delete error")));
    }

    #[test]
    fn test_store_credential_regressions_and_error_propagation() {
        // 1. Existing valid credential -> CredentialAlreadyExists with real username
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "testuser", "token_1")
            .unwrap();
        let res_exists = store.store_credential("codeberg.org", "newuser", "token_2");
        assert!(matches!(
            res_exists,
            Err(AppError::CredentialAlreadyExists { host, username })
                if host == "codeberg.org" && username == "testuser"
        ));

        // 2. Existing credential with empty username -> MalformedCredential
        let store_empty = MockCredentialStore::new();
        {
            let mut items = store_empty.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "".to_string(),
                "token_1".to_string(),
            ));
        }
        let res_empty = store_empty.store_credential("codeberg.org", "newuser", "token_2");
        assert!(matches!(
            res_empty,
            Err(AppError::MalformedCredential(host)) if host == "codeberg.org"
        ));

        // 3. Existing credential with whitespace username -> MalformedCredential
        let store_ws = MockCredentialStore::new();
        {
            let mut items = store_ws.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "   ".to_string(),
                "token_1".to_string(),
            ));
        }
        let res_ws = store_ws.store_credential("codeberg.org", "newuser", "token_2");
        assert!(matches!(
            res_ws,
            Err(AppError::MalformedCredential(host)) if host == "codeberg.org"
        ));

        // 4. Multiple existing items -> DuplicateCredentials
        let store_dup = MockCredentialStore::new();
        {
            let mut items = store_dup.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "user1".to_string(),
                "tok1".to_string(),
            ));
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "user2".to_string(),
                "tok2".to_string(),
            ));
        }
        let res_dup = store_dup.store_credential("codeberg.org", "newuser", "token_2");
        assert!(matches!(
            res_dup,
            Err(AppError::DuplicateCredentials(host)) if host == "codeberg.org"
        ));

        // 5. Search failure -> propagated
        let store_search_fail = MockCredentialStore::new();
        store_search_fail.fail_search.store(true, Ordering::SeqCst);
        let res_search = store_search_fail.store_credential("codeberg.org", "testuser", "token_1");
        assert!(matches!(
            res_search,
            Err(AppError::SecretService(msg)) if msg.contains("search error")
        ));

        // 6. Attribute retrieval failure -> propagated
        let store_attr_fail = MockCredentialStore::new();
        {
            let mut items = store_attr_fail.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "testuser".to_string(),
                "token_1".to_string(),
            ));
        }
        store_attr_fail
            .fail_attributes
            .store(true, Ordering::SeqCst);
        let res_attr = store_attr_fail.store_credential("codeberg.org", "testuser", "token_2");
        assert!(matches!(
            res_attr,
            Err(AppError::SecretService(msg)) if msg.contains("attribute error")
        ));
    }

    #[test]
    fn test_credential_file_lock_mutual_exclusion() {
        let lock1 = CredentialLock::acquire().unwrap();

        let lock_dir = resolve_secure_runtime_dir().unwrap();
        let uid = unsafe { libc::getuid() };
        let lock_path = lock_dir.join(format!("cbpkg-cred-{uid}.lock"));

        let file2 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();

        use std::os::unix::io::AsRawFd;
        let ret = unsafe { libc::flock(file2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(ret, -1);
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap();
        assert!(errno == libc::EWOULDBLOCK || errno == libc::EAGAIN);

        drop(lock1);

        let ret2 = unsafe { libc::flock(file2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(ret2, 0);
        unsafe {
            libc::flock(file2.as_raw_fd(), libc::LOCK_UN);
        }
    }

    #[test]
    fn test_runtime_dir_validation_rejects_symlink() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("real_dir");
        std::fs::create_dir_all(&target_dir).unwrap();
        let symlink_path = temp_dir.path().join("symlink_dir");
        std::os::unix::fs::symlink(&target_dir, &symlink_path).unwrap();

        let uid = unsafe { libc::getuid() };
        assert!(!validate_runtime_dir(&symlink_path, uid).unwrap());
        assert!(CredentialLock::acquire_in_dir(&symlink_path).is_err());
    }

    #[test]
    fn test_runtime_dir_validation_rejects_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir = tempfile::tempdir().unwrap();
        let insecure_dir = temp_dir.path().join("insecure_dir");
        std::fs::create_dir_all(&insecure_dir).unwrap();
        std::fs::set_permissions(&insecure_dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let uid = unsafe { libc::getuid() };
        assert!(!validate_runtime_dir(&insecure_dir, uid).unwrap());
        assert!(CredentialLock::acquire_in_dir(&insecure_dir).is_err());
    }

    #[test]
    fn test_runtime_dir_validation_accepts_secure_dir() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir = tempfile::tempdir().unwrap();
        let secure_dir = temp_dir.path().join("secure_dir");
        std::fs::create_dir_all(&secure_dir).unwrap();
        std::fs::set_permissions(&secure_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let uid = unsafe { libc::getuid() };
        assert!(validate_runtime_dir(&secure_dir, uid).unwrap());
        let lock = CredentialLock::acquire_in_dir(&secure_dir);
        assert!(lock.is_ok());

        // Verify lock file mode is 0600
        let lock_file = secure_dir.join(format!("cbpkg-cred-{uid}.lock"));
        let meta = std::fs::metadata(&lock_file).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn test_runtime_dir_lock_rejects_symlink_lock_file() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir = tempfile::tempdir().unwrap();
        let secure_dir = temp_dir.path().join("secure_dir");
        std::fs::create_dir_all(&secure_dir).unwrap();
        std::fs::set_permissions(&secure_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let uid = unsafe { libc::getuid() };
        let lock_file = secure_dir.join(format!("cbpkg-cred-{uid}.lock"));
        let fake_target = temp_dir.path().join("fake_target");
        std::fs::write(&fake_target, b"dummy").unwrap();
        std::os::unix::fs::symlink(&fake_target, &lock_file).unwrap();

        // O_NOFOLLOW must cause acquire_in_dir to fail
        let res = CredentialLock::acquire_in_dir(&secure_dir);
        assert!(res.is_err());
    }

    #[test]
    fn test_concurrent_racing_store_credential_cannot_replace_silently() {
        use std::sync::Arc;
        let store = Arc::new(MockCredentialStore::new());
        let mut handles = Vec::new();

        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let token = format!("token_{i}");
                let username = format!("user_{i}");
                store_clone.store_credential("codeberg.org", &username, &token)
            }));
        }

        let mut success_count = 0;
        let mut already_exists_count = 0;

        for h in handles {
            match h.join().unwrap() {
                Ok(()) => success_count += 1,
                Err(AppError::CredentialAlreadyExists { .. }) => already_exists_count += 1,
                Err(e) => panic!("Unexpected error during concurrent store: {e}"),
            }
        }

        assert_eq!(success_count, 1);
        assert_eq!(already_exists_count, 9);

        let items = store.items.lock().unwrap();
        assert_eq!(items.len(), 1);
    }
}
