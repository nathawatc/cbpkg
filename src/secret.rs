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
        let ss = SecretService::connect(EncryptionType::Plain)
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
        let ss = SecretService::connect(EncryptionType::Plain)
            .map_err(|e| AppError::SecretService(e.to_string()))?;

        let collection = ss.get_default_collection().map_err(|e| {
            AppError::SecretService(format!("Failed to get default collection: {e}"))
        })?;

        collection
            .ensure_unlocked()
            .map_err(|_| AppError::CollectionLocked)?;

        // Remove any existing cbpkg items for this host to prevent duplicate entries
        let mut search_attrs = HashMap::new();
        search_attrs.insert("application", APP_ID);
        search_attrs.insert("host", host);

        if let Ok(existing_items) = collection.search_items(search_attrs) {
            for item in existing_items {
                let _ = item.delete();
            }
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
        let ss = SecretService::connect(EncryptionType::Plain)
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

    #[derive(Default)]
    pub struct MockCredentialStore {
        entries: std::sync::Mutex<HashMap<(String, String), SecretCredential>>,
    }

    impl MockCredentialStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl CredentialStore for MockCredentialStore {
        fn get_credential(&self, host: &str) -> Result<Option<SecretCredential>, AppError> {
            let map = self.entries.lock().unwrap();
            let key = (APP_ID.to_string(), host.to_string());
            Ok(map.get(&key).cloned())
        }

        fn store_credential(
            &self,
            host: &str,
            username: &str,
            token: &str,
        ) -> Result<(), AppError> {
            let mut map = self.entries.lock().unwrap();
            let key = (APP_ID.to_string(), host.to_string());
            map.insert(
                key,
                SecretCredential {
                    username: username.to_string(),
                    token: token.to_string(),
                },
            );
            Ok(())
        }

        fn delete_credential(&self, host: &str) -> Result<bool, AppError> {
            let mut map = self.entries.lock().unwrap();
            let key = (APP_ID.to_string(), host.to_string());
            Ok(map.remove(&key).is_some())
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
    fn test_mock_credential_store_workflow() {
        let store = MockCredentialStore::new();

        // 1. Initial status: not found
        assert_eq!(store.get_credential("codeberg.org").unwrap(), None);

        // 2. Store credential
        store
            .store_credential("codeberg.org", "nathawat", "token_a")
            .unwrap();
        let cred = store.get_credential("codeberg.org").unwrap().unwrap();
        assert_eq!(cred.username, "nathawat");
        assert_eq!(cred.token, "token_a");

        // 3. Replacement of existing credential
        store
            .store_credential("codeberg.org", "nathawat", "token_b")
            .unwrap();
        let cred2 = store.get_credential("codeberg.org").unwrap().unwrap();
        assert_eq!(cred2.token, "token_b");

        // 4. Scoped isolation: different host not affected
        assert_eq!(store.get_credential("other.org").unwrap(), None);

        // 5. Delete credential
        assert!(store.delete_credential("codeberg.org").unwrap());
        assert_eq!(store.get_credential("codeberg.org").unwrap(), None);

        // 6. Delete idempotent (returns false when not present)
        assert!(!store.delete_credential("codeberg.org").unwrap());
    }
}
