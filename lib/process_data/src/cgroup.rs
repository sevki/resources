use lazy_regex::{Lazy, Regex, lazy_regex};

static RE_CGROUP: Lazy<Regex> = lazy_regex!(
    r"(?U)/(?:app|background)\.slice/(?:[^/]+/)*(?:app-|dbus-:)(?:(?P<launcher>[^-]+)-)?(?P<cgroup>[^-]+)(?:-[0-9]+|@[0-9]+)?\.(?:scope|service)"
);

/* The cgroup of a snap process is composed of: `snap.<snap-name>.<app-name>-<uuid>.scope`
 * The name has the following restrictions:
 *  > It must start with an ASCII character and can only contain lower case letters, numbers, and hyphens.
 *  > It must contain at least one letter and it can't start or end with a hyphen.
 * https://documentation.ubuntu.com/snapcraft/8.9.4/reference/project-file/snapcraft-yaml/#name
 *
 * Furthermore, the snap name may contain a single '_' character that denotes a specific instance of this snap.
 * https://snapcraft.io/docs/explanation/how-snaps-work/parallel-installs/#installing-multiple-instances
 *
 * Because '-' is both the separator character before the uuid as well as a valid character for the names,
 * we must try to match the start of the uuid group exactly.
 */
static RE_SNAP_CGROUP: Lazy<Regex> = lazy_regex!(
    r"/snap\.(?P<cgroup>[_\-0-9a-z]+\.[\-0-9a-z]+)(?:-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\.(?:scope|service)"
);

// apparently some apps like mullvad do this to include a '-' in their cgroup even though that's
// not allowed.
fn decode_hex_escapes(s: &str) -> Result<String, ()> {
    #[inline]
    const fn hex(b: u8) -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            let hi = bytes[i + 2];
            let lo = bytes[i + 3];

            let val = (hex(hi)? << 4) | hex(lo)?;
            out.push(val);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(out).map_err(|_| ())
}

/// extracts `(launcher, cgroup)` from the raw contents of `/proc/<pid>/cgroup`, handling both
/// the regular app/background slice format and the snap-specific format.
#[must_use]
pub fn sanitize_cgroup<S: AsRef<str>>(cgroup: S) -> (Option<String>, Option<String>) {
    RE_CGROUP
        .captures(cgroup.as_ref())
        .map(|captures| {
            (
                captures
                    .name("launcher")
                    .and_then(|s| decode_hex_escapes(s.as_str()).ok()),
                captures
                    .name("cgroup")
                    .and_then(|s| decode_hex_escapes(s.as_str()).ok()),
            )
        })
        .or_else(|| {
            RE_SNAP_CGROUP.captures(cgroup.as_ref()).map(|captures| {
                (
                    Some("snap".to_string()),
                    captures
                        .name("cgroup")
                        .and_then(|s| decode_hex_escapes(s.as_str()).ok()),
                )
            })
        })
        .unwrap_or_default()
}
