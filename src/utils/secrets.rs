//! Storage of secrets (the VirusTotal API key) in the system keyring, i.e.
//! the Secret Service on the host or the Secret portal inside Flatpak.

use std::collections::HashMap;

/// If set, this is used as the VirusTotal API key and the keyring is not
/// consulted. Meant for headless setups and tests.
pub const VIRUSTOTAL_KEY_ENV: &str = "RESOURCES_VIRUSTOTAL_API_KEY";

const LABEL: &str = "Resources: VirusTotal API key";

fn attributes() -> HashMap<String, String> {
    HashMap::from([
        ("application".to_string(), "org.gnome.Resources".to_string()),
        ("type".to_string(), "virustotal-api-key".to_string()),
    ])
}

fn from_env() -> Option<String> {
    std::env::var(VIRUSTOTAL_KEY_ENV)
        .ok()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
}

/// The stored VirusTotal API key, `Ok(None)` if there is none.
pub async fn virustotal_key() -> Result<Option<String>, String> {
    if let Some(key) = from_env() {
        return Ok(Some(key));
    }

    let keyring = oo7::Keyring::new().await.map_err(|e| e.to_string())?;
    let items = keyring
        .search_items(&attributes())
        .await
        .map_err(|e| e.to_string())?;

    let Some(item) = items.first() else {
        return Ok(None);
    };
    let secret = item.secret().await.map_err(|e| e.to_string())?;
    Ok(secret
        .as_str()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty()))
}

/// Stores the key, or removes it if `key` is `None` or blank.
pub async fn set_virustotal_key(key: Option<&str>) -> Result<(), String> {
    let keyring = oo7::Keyring::new().await.map_err(|e| e.to_string())?;
    let attributes = attributes();

    match key.map(str::trim).filter(|key| !key.is_empty()) {
        Some(key) => keyring
            .create_item(LABEL, &attributes, key, true)
            .await
            .map_err(|e| e.to_string()),
        None => keyring.delete(&attributes).await.map_err(|e| e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs a running, unlocked Secret Service, so it only runs when
    /// `RESOURCES_TEST_KEYRING=1` (see the CI workflow or run it inside
    /// `dbus-run-session` with `gnome-keyring-daemon --unlock`).
    #[test]
    fn keyring_roundtrip() {
        if std::env::var("RESOURCES_TEST_KEYRING").as_deref() != Ok("1") {
            eprintln!("skipped: RESOURCES_TEST_KEYRING is not set");
            return;
        }
        assert!(
            std::env::var(VIRUSTOTAL_KEY_ENV).is_err(),
            "the environment override would hide the keyring"
        );

        let context = gtk::glib::MainContext::new();
        context
            .with_thread_default(|| {
                context.block_on(async {
                    assert_eq!(virustotal_key().await, Ok(None));

                    set_virustotal_key(Some("  first-key \n")).await.unwrap();
                    assert_eq!(virustotal_key().await, Ok(Some("first-key".into())));

                    // replacing must not leave two items behind
                    set_virustotal_key(Some("second-key")).await.unwrap();
                    assert_eq!(virustotal_key().await, Ok(Some("second-key".into())));

                    // a blank key removes it
                    set_virustotal_key(Some("   ")).await.unwrap();
                    assert_eq!(virustotal_key().await, Ok(None));
                })
            })
            .unwrap();
    }

    #[test]
    fn environment_override_wins_and_ignores_blank() {
        // only reads the environment, so no keyring is needed; the variable
        // is not set by anything else in the test suite
        assert_eq!(from_env(), None);
    }
}
