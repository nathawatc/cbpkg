use crate::error::AppError;
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use std::collections::HashMap;
use std::fmt;

pub const APP_ID: &str = "cbpkg";
pub const ITEM_LABEL: &str = "cbpkg Codeberg token";

#[derive(Clone, PartialEq, Eq)]
pub struct SecretCredential {
    pub username: String,
    pub token: String,
}

impl fmt::Debug for SecretCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretCredential")
            .field("username", &self.username)
            .field("token", &"<redacted>")
            .finish()
    }
}

pub trait CredentialStore: Send + Sync {
    fn get_credential(&self, host: &str) -> Result<Option<SecretCredential>, AppError>;
    fn store_credential(&self, host: &str, username: &str, token: &str) -> Result<(), AppError>;
    fn delete_credential(&self, host: &str) -> Result<bool, AppError>;
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
    fn get_credential(&self, host: &str) -> Result<Option<SecretCredential>, AppError> {
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
        search_attrs.insert("host", host);

        let items = collection
            .search_items(search_attrs)
            .map_err(|e| AppError::SecretService(format!("Search items failed: {e}")))?;

        if items.is_empty() {
            return Ok(None);
        }

        let item = &items[0];
        let attrs = item
            .get_attributes()
            .map_err(|e| AppError::SecretService(format!("Failed to get item attributes: {e}")))?;

        let username = attrs
            .get("username")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let secret_bytes = item
            .get_secret()
            .map_err(|e| AppError::SecretService(format!("Failed to read secret payload: {e}")))?;

        let token = String::from_utf8(secret_bytes)
            .map_err(|e| AppError::SecretService(format!("Secret is not valid UTF-8: {e}")))?;

        Ok(Some(SecretCredential { username, token }))
    }

    fn store_credential(&self, host: &str, username: &str, token: &str) -> Result<(), AppError> {
        let ss = SecretService::connect(EncryptionType::Dh)
            .map_err(|e| AppError::SecretService(e.to_string()))?;

        let collection = ss.get_default_collection().map_err(|e| {
            AppError::SecretService(format!("Failed to get default collection: {e}"))
        })?;

        collection
            .ensure_unlocked()
            .map_err(|_| AppError::CollectionLocked)?;

        // Search for existing cbpkg credentials and strictly propagate search errors
        let mut search_attrs = HashMap::new();
        search_attrs.insert("application", APP_ID);
        search_attrs.insert("host", host);

        let existing_items = collection
            .search_items(search_attrs)
            .map_err(|e| AppError::SecretService(format!("Search existing items failed: {e}")))?;

        // Delete all existing items deterministically and strictly propagate deletion errors
        for item in existing_items {
            item.delete().map_err(|e| {
                AppError::SecretService(format!("Failed to delete existing item: {e}"))
            })?;
        }

        let mut attrs = HashMap::new();
        attrs.insert("application", APP_ID);
        attrs.insert("host", host);
        attrs.insert("username", username);

        collection
            .create_item(ITEM_LABEL, attrs, token.as_bytes(), true, "text/plain")
            .map_err(|e| AppError::SecretService(format!("Failed to create secret item: {e}")))?;

        Ok(())
    }

    fn delete_credential(&self, host: &str) -> Result<bool, AppError> {
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
        search_attrs.insert("host", host);

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
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    pub struct MockCredentialStore {
        pub items: std::sync::Mutex<Vec<(String, String, String, String)>>,
        pub fail_search: AtomicBool,
        pub fail_delete: AtomicBool,
    }

    impl MockCredentialStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl CredentialStore for MockCredentialStore {
        fn get_credential(&self, host: &str) -> Result<Option<SecretCredential>, AppError> {
            if self.fail_search.load(Ordering::SeqCst) {
                return Err(AppError::SecretService(
                    "Simulated search error".to_string(),
                ));
            }
            let items = self.items.lock().unwrap();
            for (app, h, u, t) in items.iter() {
                if app == APP_ID && h == host {
                    return Ok(Some(SecretCredential {
                        username: u.clone(),
                        token: t.clone(),
                    }));
                }
            }
            Ok(None)
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

            let mut items = self.items.lock().unwrap();
            items.retain(|(app, h, _, _)| !(app == APP_ID && h == host));
            items.push((
                APP_ID.to_string(),
                host.to_string(),
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

            let mut items = self.items.lock().unwrap();
            let before = items.len();
            items.retain(|(app, h, _, _)| !(app == APP_ID && h == host));
            Ok(items.len() < before)
        }
    }

    #[test]
    fn test_secret_credential_debug_redacted() {
        let cred = SecretCredential {
            username: "nathawat".to_string(),
            token: "secret_token_12345".to_string(),
        };
        let debug_str = format!("{cred:?}");
        assert!(!debug_str.contains("secret_token_12345"));
        assert!(debug_str.contains("<redacted>"));
        assert!(debug_str.contains("nathawat"));
    }

    #[test]
    fn test_credential_replacement() {
        let store = MockCredentialStore::new();

        store
            .store_credential("codeberg.org", "nathawat", "token_a")
            .unwrap();
        let cred1 = store.get_credential("codeberg.org").unwrap().unwrap();
        assert_eq!(cred1.token, "token_a");

        store
            .store_credential("codeberg.org", "nathawat", "token_b")
            .unwrap();
        let cred2 = store.get_credential("codeberg.org").unwrap().unwrap();
        assert_eq!(cred2.token, "token_b");

        let items = store.items.lock().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].3, "token_b");
    }

    #[test]
    fn test_search_failure_propagation() {
        let store = MockCredentialStore::new();
        store.fail_search.store(true, Ordering::SeqCst);

        let res = store.store_credential("codeberg.org", "nathawat", "token_a");
        assert!(matches!(res, Err(AppError::SecretService(msg)) if msg.contains("search error")));
        assert!(store.items.lock().unwrap().is_empty());
    }

    #[test]
    fn test_delete_failure_propagation() {
        let store = MockCredentialStore::new();
        store
            .store_credential("codeberg.org", "nathawat", "token_a")
            .unwrap();

        store.fail_delete.store(true, Ordering::SeqCst);

        let res = store.store_credential("codeberg.org", "nathawat", "token_b");
        assert!(matches!(res, Err(AppError::SecretService(msg)) if msg.contains("delete error")));

        // Token_a was not overwritten or removed
        let cred = store.get_credential("codeberg.org").unwrap().unwrap();
        assert_eq!(cred.token, "token_a");
    }

    #[test]
    fn test_duplicate_handling() {
        let store = MockCredentialStore::new();
        // Artificially inject multiple cbpkg duplicate entries for the host
        {
            let mut items = store.items.lock().unwrap();
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "nathawat".to_string(),
                "old_token_1".to_string(),
            ));
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "nathawat".to_string(),
                "old_token_2".to_string(),
            ));
        }

        // Store new credential
        store
            .store_credential("codeberg.org", "nathawat", "new_token")
            .unwrap();

        let items = store.items.lock().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].3, "new_token");
    }

    #[test]
    fn test_logout_isolation() {
        let store = MockCredentialStore::new();
        {
            let mut items = store.items.lock().unwrap();
            items.push((
                "other_app".to_string(),
                "codeberg.org".to_string(),
                "user_other".to_string(),
                "token_other".to_string(),
            ));
            items.push((
                APP_ID.to_string(),
                "gitlab.com".to_string(),
                "user_gitlab".to_string(),
                "token_gitlab".to_string(),
            ));
            items.push((
                APP_ID.to_string(),
                "codeberg.org".to_string(),
                "nathawat".to_string(),
                "token_codeberg".to_string(),
            ));
        }

        // Logout from codeberg.org
        assert!(store.delete_credential("codeberg.org").unwrap());

        // Verify other app and other host were not deleted
        let items = store.items.lock().unwrap();
        assert_eq!(items.len(), 2);
        assert!(
            items
                .iter()
                .any(|(app, h, _, _)| app == "other_app" && h == "codeberg.org")
        );
        assert!(
            items
                .iter()
                .any(|(app, h, _, _)| app == APP_ID && h == "gitlab.com")
        );
        assert!(
            !items
                .iter()
                .any(|(app, h, _, _)| app == APP_ID && h == "codeberg.org")
        );
    }
}
