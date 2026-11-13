//! Named sets of visible columns of the Processes view, like Process
//! Explorer's column sets.
//!
//! Sets are stored as a JSON array of `{"name": …, "columns": […]}` in the
//! `processes-column-sets` setting; `columns` lists the `processes-show-*`
//! settings keys that are switched on in that set.

use serde_json::{Value, json};

/// All settings keys that toggle a column of the Processes view.
pub const COLUMN_KEYS: [&str; 20] = [
    "processes-show-id",
    "processes-show-user",
    "processes-show-memory",
    "processes-show-cpu",
    "processes-show-drive-read-speed",
    "processes-show-drive-read-total",
    "processes-show-drive-write-speed",
    "processes-show-drive-write-total",
    "processes-show-gpu",
    "processes-show-encoder",
    "processes-show-decoder",
    "processes-show-gpu-memory",
    "processes-show-total-cpu-time",
    "processes-show-user-cpu-time",
    "processes-show-system-cpu-time",
    "processes-show-priority",
    "processes-show-swap",
    "processes-show-combined-memory",
    "processes-show-commandline",
    "processes-show-virustotal",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnSet {
    pub name: String,
    pub columns: Vec<String>,
}

impl ColumnSet {
    /// For every known column key, whether this set shows it. Unknown keys in
    /// the set (e.g. from a newer version) are ignored.
    pub fn visibility(&self) -> Vec<(&'static str, bool)> {
        COLUMN_KEYS
            .iter()
            .map(|key| (*key, self.columns.iter().any(|column| column == key)))
            .collect()
    }
}

/// Parses the stored JSON, tolerating (and dropping) malformed entries.
pub fn parse(json: &str) -> Vec<ColumnSet> {
    let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };

    let mut sets: Vec<ColumnSet> = Vec::new();
    for entry in entries {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || sets.iter().any(|set| set.name == name) {
            continue;
        }
        let columns = entry
            .get("columns")
            .and_then(Value::as_array)
            .map(|columns| {
                columns
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        sets.push(ColumnSet {
            name: name.to_string(),
            columns,
        });
    }
    sets
}

pub fn serialize(sets: &[ColumnSet]) -> String {
    Value::Array(
        sets.iter()
            .map(|set| json!({ "name": set.name, "columns": set.columns }))
            .collect(),
    )
    .to_string()
}

/// Adds a set, replacing an existing one of the same name. Returns `false`
/// (and does nothing) if the name is empty.
pub fn upsert(sets: &mut Vec<ColumnSet>, name: &str, columns: Vec<String>) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    let new = ColumnSet {
        name: name.to_string(),
        columns,
    };
    match sets.iter_mut().find(|set| set.name == name) {
        Some(existing) => *existing = new,
        None => sets.push(new),
    }
    true
}

pub fn remove(sets: &mut Vec<ColumnSet>, name: &str) -> bool {
    let before = sets.len();
    sets.retain(|set| set.name != name);
    sets.len() != before
}

/// Keys of the columns that are currently shown according to `is_enabled`.
pub fn current(is_enabled: impl Fn(&str) -> bool) -> Vec<String> {
    COLUMN_KEYS
        .iter()
        .filter(|key| is_enabled(key))
        .map(|key| (*key).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let sets = vec![
            ColumnSet {
                name: "Memory".into(),
                columns: vec!["processes-show-memory".into(), "processes-show-swap".into()],
            },
            ColumnSet {
                name: "Disk, \"IO\"".into(),
                columns: vec![],
            },
        ];
        assert_eq!(parse(&serialize(&sets)), sets);
    }

    #[test]
    fn parse_is_tolerant() {
        assert!(parse("").is_empty());
        assert!(parse("not json").is_empty());
        assert!(parse("{}").is_empty());
        let sets = parse(
            r#"[{"name":"a","columns":["x",1,"y"]},{"columns":[]},{"name":"  "},{"name":"a"},42,{"name":"b"}]"#,
        );
        assert_eq!(
            sets,
            vec![
                ColumnSet {
                    name: "a".into(),
                    columns: vec!["x".into(), "y".into()]
                },
                ColumnSet {
                    name: "b".into(),
                    columns: vec![]
                },
            ]
        );
    }

    #[test]
    fn upsert_and_remove() {
        let mut sets = Vec::new();
        assert!(!upsert(&mut sets, "   ", vec![]));
        assert!(upsert(&mut sets, " one ", vec!["processes-show-id".into()]));
        assert!(upsert(&mut sets, "one", vec!["processes-show-cpu".into()]));
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].name, "one");
        assert_eq!(sets[0].columns, vec!["processes-show-cpu"]);
        assert!(remove(&mut sets, "one"));
        assert!(!remove(&mut sets, "one"));
        assert!(sets.is_empty());
    }

    #[test]
    fn visibility_covers_all_keys_and_ignores_unknown() {
        let set = ColumnSet {
            name: "x".into(),
            columns: vec![
                "processes-show-cpu".into(),
                "processes-show-from-the-future".into(),
            ],
        };
        let visibility = set.visibility();
        assert_eq!(visibility.len(), COLUMN_KEYS.len());
        assert!(visibility.contains(&("processes-show-cpu", true)));
        assert!(visibility.contains(&("processes-show-id", false)));
    }

    #[test]
    fn current_uses_known_keys_in_order() {
        let enabled = current(|key| key == "processes-show-memory" || key == "processes-show-id");
        assert_eq!(enabled, vec!["processes-show-id", "processes-show-memory"]);
    }

    #[test]
    fn keys_match_schema() {
        let schema = include_str!("../../data/org.gnome.Resources.gschema.xml.in");
        for key in COLUMN_KEYS {
            assert!(schema.contains(&format!("<key name=\"{key}\"")), "{key}");
        }
        let schema_columns = schema.matches("<key name=\"processes-show-").count();
        // processes-show-details is not a column
        assert_eq!(schema_columns - 1, COLUMN_KEYS.len());
    }
}
