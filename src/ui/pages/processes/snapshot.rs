//! Exporting the process list, like Process Explorer's File → Save.

/// Quotes a CSV field if necessary (RFC 4180).
fn csv_field(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Builds a CSV document from a header and rows.
pub fn to_csv(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = header
        .iter()
        .map(|field| csv_field(field))
        .collect::<Vec<_>>()
        .join(",");
    out.push('\n');
    for row in rows {
        out.push_str(
            &row.iter()
                .map(|f| csv_field(f))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_when_needed() {
        let csv = to_csv(
            &["name", "cmd"],
            &[
                vec!["plain".into(), "a b".into()],
                vec!["with,comma".into(), "say \"hi\"".into()],
                vec!["multi\nline".into(), String::new()],
            ],
        );
        assert_eq!(
            csv,
            "name,cmd\nplain,a b\n\"with,comma\",\"say \"\"hi\"\"\"\n\"multi\nline\",\n"
        );
    }
}
