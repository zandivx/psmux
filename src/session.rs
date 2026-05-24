use std::io::{self, Write};
use std::time::Duration;
use std::env;

/// Returns true if this port-file base name belongs to a warm (standby) server.
/// Warm sessions should be hidden from user-facing lists and never auto-attached.
pub fn is_warm_session(base: &str) -> bool {
    base == "__warm__" || base.ends_with("____warm__")
}

/// Find the next available numeric session name (tmux-compatible).
/// tmux uses a monotonically incrementing counter, but since psmux has
/// no persistent server state, we scan existing port files and pick
/// the lowest non-negative integer not already in use.
/// When `ns_prefix` is Some("foo"), names are checked as "foo__0", "foo__1", etc.
pub fn next_session_name(ns_prefix: Option<&str>) -> String {
    let home = match env::var("USERPROFILE").or_else(|_| env::var("HOME")) {
        Ok(h) => h,
        Err(_) => return "0".to_string(),
    };
    let psmux_dir = format!("{}\\.psmux", home);
    let mut used: std::collections::HashSet<u32> = std::collections::HashSet::new();
    if let Ok(entries) = std::fs::read_dir(&psmux_dir) {
        for entry in entries.flatten() {
            if let Some(fname) = entry.file_name().to_str() {
                if let Some((base, ext)) = fname.rsplit_once('.') {
                    if ext != "port" { continue; }
                    if is_warm_session(base) { continue; }
                    // Extract the session name part (after namespace prefix if any)
                    let session_part = if let Some(pfx) = ns_prefix {
                        let full_pfx = format!("{}__", pfx);
                        if base.starts_with(&full_pfx) {
                            &base[full_pfx.len()..]
                        } else {
                            continue; // different namespace
                        }
                    } else {
                        if base.contains("__") { continue; } // namespaced session
                        base
                    };
                    if let Ok(n) = session_part.parse::<u32>() {
                        used.insert(n);
                    }
                }
            }
        }
    }
    let mut id = 0u32;
    while used.contains(&id) {
        id += 1;
    }
    id.to_string()
}

/// Clean up any stale port files (where server is not actually running)
pub fn cleanup_stale_port_files() {
    let home = match env::var("USERPROFILE").or_else(|_| env::var("HOME")) {
        Ok(h) => h,
        Err(_) => return,
    };
    let psmux_dir = format!("{}\\.psmux", home);
    if let Ok(entries) = std::fs::read_dir(&psmux_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "port").unwrap_or(false) {
                if let Ok(port_str) = std::fs::read_to_string(&path) {
                    if let Ok(port) = port_str.trim().parse::<u16>() {
                        let addr = format!("127.0.0.1:{}", port);
                        if std::net::TcpStream::connect_timeout(
                            &addr.parse().unwrap(),
                            Duration::from_millis(5)
                        ).is_err() {
                            let _ = std::fs::remove_file(&path);
                            // Also remove the matching .key file to prevent
                            // orphaned keys from accumulating (issue #136).
                            let key_path = path.with_extension("key");
                            let _ = std::fs::remove_file(&key_path);
                        }
                    } else {
                        let _ = std::fs::remove_file(&path);
                        let key_path = path.with_extension("key");
                        let _ = std::fs::remove_file(&key_path);
                    }
                }
            }
        }
    }
}

/// Read the session key from the key file
pub fn read_session_key(session: &str) -> io::Result<String> {
    let home = env::var("USERPROFILE").or_else(|_| env::var("HOME")).unwrap_or_default();
    let keypath = format!("{}\\.psmux\\{}.key", home, session);
    std::fs::read_to_string(&keypath).map(|s| s.trim().to_string())
}

/// Hard cap on a single response payload read from the server (256 KB).
///
/// The server is trusted, but the client should still bound how much memory
/// a single picker fetch can consume. A buggy or malicious peer that sends
/// an unbounded line with no `\n` would otherwise block until the read
/// timeout while filling the BufReader. 256 KB is comfortably larger than
/// any real `session-info`, `list-tree`, or `choose-buffer` payload.
pub const MAX_AUTHED_RESPONSE_BYTES: u64 = 256 * 1024;

/// Validate that a session key is well-formed for the line-oriented AUTH
/// protocol. Rejects keys containing CR, LF, or NUL — anything that could
/// terminate the AUTH line early or smuggle a second protocol frame.
///
/// Returns the trimmed key on success, `None` on rejection.
///
/// SECURITY: Without this check, a key sourced from a future caller (e.g.
/// env var, IPC, plugin) that contains `\n` could inject a second command
/// onto the AUTH line. All AUTH writers should funnel through this guard.
pub fn validate_auth_key(key: &str) -> Option<&str> {
    let k = key.trim_matches(|c: char| c == '\r' || c == '\n');
    if k.is_empty() {
        return None;
    }
    if k.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return None;
    }
    Some(k)
}

/// Send an authenticated command to a server (fire-and-forget).
///
/// Validates the key against CRLF/NUL injection. Silently no-ops on a
/// malformed key — callers are at the trust boundary already (key file
/// under user's profile), this is defense-in-depth.
pub fn send_auth_cmd(addr: &str, key: &str, cmd: &[u8]) -> io::Result<()> {
    let key = match validate_auth_key(key) {
        Some(k) => k,
        None => return Ok(()),
    };
    let sock_addr: std::net::SocketAddr = addr.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if let Ok(mut s) = std::net::TcpStream::connect_timeout(&sock_addr, Duration::from_millis(50)) {
        let _ = s.set_nodelay(true);
        let _ = write!(s, "AUTH {}\n", key);
        let _ = std::io::Write::write_all(&mut s, cmd);
        let _ = s.flush();
    }
    Ok(())
}

/// Send an authenticated command and get response.
///
/// Validates the key, caps the response at `MAX_AUTHED_RESPONSE_BYTES`,
/// and returns whatever the server sent after the AUTH ack. The `OK\n`
/// ack is **not** stripped here for backward compatibility with existing
/// callers; new code should prefer `fetch_authed_response` /
/// `fetch_authed_response_multi`.
pub fn send_auth_cmd_response(addr: &str, key: &str, cmd: &[u8]) -> io::Result<String> {
    let key = match validate_auth_key(key) {
        Some(k) => k,
        None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid session key")),
    };
    let mut s = std::net::TcpStream::connect(addr)?;
    let _ = s.set_nodelay(true);
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = write!(s, "AUTH {}\n", key);
    let _ = std::io::Write::write_all(&mut s, cmd);
    let _ = s.flush();
    let mut br = std::io::BufReader::new(std::io::Read::take(&mut s, MAX_AUTHED_RESPONSE_BYTES));
    let mut auth_line = String::new();
    let _ = std::io::BufRead::read_line(&mut br, &mut auth_line);
    let mut buf = String::new();
    let _ = std::io::Read::read_to_string(&mut br, &mut buf);
    Ok(buf)
}

/// Internal: open an authenticated connection and send a single command.
///
/// Returns a length-capped `BufReader` positioned right after the command
/// write, ready for response parsing. Centralizes:
///   - CRLF/NUL key validation (security)
///   - connect timeout, read timeout, TCP_NODELAY
///   - response size cap (`MAX_AUTHED_RESPONSE_BYTES`, DoS guard)
///   - the AUTH + command write
///
/// The size cap is applied with `Read::take` BEFORE the `BufReader` so the
/// resulting reader still exposes `BufRead`. Wrapping the other way around
/// (`BufReader::take`) loses `BufRead` because `Take` is `Read`-only.
fn open_authed(
    addr: &str,
    key: &str,
    cmd: &[u8],
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Option<std::io::BufReader<std::io::Take<std::net::TcpStream>>> {
    let key = validate_auth_key(key)?;
    let sock_addr: std::net::SocketAddr = addr.parse().ok()?;
    let mut s = std::net::TcpStream::connect_timeout(&sock_addr, connect_timeout).ok()?;
    s.set_read_timeout(Some(read_timeout)).ok()?;
    let _ = s.set_nodelay(true);
    write!(s, "AUTH {}\n", key).ok()?;
    s.write_all(cmd).ok()?;
    if !cmd.ends_with(b"\n") {
        s.write_all(b"\n").ok()?;
    }
    let _ = s.flush();
    Some(std::io::BufReader::new(std::io::Read::take(s, MAX_AUTHED_RESPONSE_BYTES)))
}

/// Read one response line from an authenticated stream, transparently
/// skipping the `OK\n` AUTH ack regardless of when it arrives.
///
/// Returns `None` on timeout, EOF, empty payload, or `ERROR:` reply.
/// Returns `Some(line)` on a valid payload (newline trimmed).
fn read_authed_line<R: std::io::BufRead>(br: &mut R) -> Option<String> {
    // First read: could be either the AUTH ack ("OK") or the payload
    // (if the ack was already pipelined into the same packet).
    let mut line = String::new();
    if std::io::BufRead::read_line(br, &mut line).ok()? == 0 {
        return None;
    }
    let trimmed = line.trim();
    if trimmed == "OK" {
        // First line WAS the ack. Read the real payload now.
        line.clear();
        if std::io::BufRead::read_line(br, &mut line).ok()? == 0 {
            return None;
        }
    }
    // Filter again in case the second line is also empty/error/OK.
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed == "OK" || trimmed.starts_with("ERROR:") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Read all remaining bytes from an authenticated stream, stripping a
/// leading `OK\n` AUTH ack if present.
///
/// Returns `None` on no payload, error response, or read failure.
/// Returns `Some(payload)` with the AUTH ack removed and trailing
/// whitespace stripped. Total read is capped by the underlying `Take`.
fn read_authed_all<R: std::io::Read>(rd: &mut R) -> Option<String> {
    let mut buf = String::new();
    std::io::Read::read_to_string(rd, &mut buf).ok()?;
    let body = buf.strip_prefix("OK\n").or_else(|| buf.strip_prefix("OK\r\n")).unwrap_or(&buf);
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed.starts_with("ERROR:") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Send an authenticated single-command request and return one response line.
///
/// Centralized AUTH + command + response helper used by all picker fetches.
/// Handles every known framing race for the AUTH ack:
///   - ack pipelined with payload (one packet, both lines arrive together)
///   - ack arrives first, then payload
///   - ack delayed past first read (issue #250 race)
///   - server replies only `OK` and never sends payload
///   - server replies `ERROR: ...`
///   - server hangs / connection refused / bad address
///
/// All callers get the same robust behavior; they can no longer reinvent
/// the parser per-site (which is how #250 happened).
pub fn fetch_authed_response(
    addr: &str,
    key: &str,
    cmd: &[u8],
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Option<String> {
    let mut br = open_authed(addr, key, cmd, connect_timeout, read_timeout)?;
    read_authed_line(&mut br)
}

/// Like `fetch_authed_response` but returns the entire response body
/// (multi-line payloads such as `list-tree` JSON arrays or `choose-buffer`
/// listings). The leading AUTH ack line is stripped if present.
///
/// The total payload is bounded by `MAX_AUTHED_RESPONSE_BYTES` to prevent
/// a malformed or hostile server from forcing unbounded client memory.
pub fn fetch_authed_response_multi(
    addr: &str,
    key: &str,
    cmd: &[u8],
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Option<String> {
    let mut br = open_authed(addr, key, cmd, connect_timeout, read_timeout)?;
    read_authed_all(&mut br)
}

/// Fetch a one-line `session-info` response from a session server.
///
/// Thin wrapper over `fetch_authed_response` retained for the call site
/// in `client.rs` (and the regression tests added in PR #251 for #250).
pub fn fetch_session_info(
    addr: &str,
    key: &str,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Option<String> {
    fetch_authed_response(addr, key, b"session-info\n", connect_timeout, read_timeout)
}

/// Fan out `fetch_session_info` across many sessions in parallel.
///
/// The session picker used to call `fetch_session_info` sequentially, so
/// opening the picker with N sessions was bounded by `N * read_timeout`
/// in the worst case. With this helper, N concurrent threads share that
/// bound: total wall time is roughly `read_timeout`, regardless of N.
///
/// `inputs` is `(label, addr, key)`. Output preserves input order and
/// pairs each label with the fetched info or the supplied `fallback`
/// (typically `"<label>: (not responding)"`).
pub fn fetch_session_infos_parallel<F>(
    inputs: Vec<(String, String, String)>,
    connect_timeout: Duration,
    read_timeout: Duration,
    fallback: F,
) -> Vec<(String, String)>
where
    F: Fn(&str) -> String + Send + Sync,
{
    if inputs.is_empty() {
        return Vec::new();
    }
    // Single session: skip thread spawn overhead entirely.
    if inputs.len() == 1 {
        let (label, addr, key) = &inputs[0];
        let info = fetch_session_info(addr, key, connect_timeout, read_timeout)
            .unwrap_or_else(|| fallback(label));
        return vec![(label.clone(), info)];
    }
    let results: Vec<(String, String)> = std::thread::scope(|scope| {
        let fallback_ref = &fallback;
        let handles: Vec<_> = inputs
            .iter()
            .map(|(label, addr, key)| {
                let label = label.clone();
                let addr = addr.clone();
                let key = key.clone();
                scope.spawn(move || {
                    let info = fetch_session_info(&addr, &key, connect_timeout, read_timeout)
                        .unwrap_or_else(|| fallback_ref(&label));
                    (label, info)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    results
}

pub fn send_control(line: String) -> io::Result<()> {
    let home = env::var("USERPROFILE").or_else(|_| env::var("HOME")).unwrap_or_default();
    let mut target = env::var("PSMUX_TARGET_SESSION").ok().unwrap_or_else(|| "default".to_string());
    // Never target a warm (standby) session — resolve to a real session instead
    if is_warm_session(&target) {
        // Extract namespace from warm session name (e.g. "foo____warm__" -> Some("foo"))
        let ns = target.strip_suffix("____warm__").map(|s| s.to_string());
        target = resolve_last_session_name_ns(ns.as_deref()).unwrap_or_else(|| "default".to_string());
    }
    let full_target = env::var("PSMUX_TARGET_FULL").ok();
    let path = format!("{}\\.psmux\\{}.port", home, target);
    let port = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse::<u16>().ok()).ok_or_else(|| io::Error::new(io::ErrorKind::Other, format!("no server running on session '{}'", target)))?.clone();
    let session_key = read_session_key(&target).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100))?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let _ = write!(stream, "AUTH {}\n", session_key);
    if let Some(ref ft) = full_target {
        let _ = write!(stream, "TARGET {}\n", ft);
    }
    let _ = write!(stream, "{}", line);
    let _ = stream.flush();
    // Read the "OK" response to drain the receive buffer before closing.
    // This prevents Windows from sending RST (due to unread data) which
    // could cause the server to lose the command.
    let mut buf = [0u8; 64];
    let _ = std::io::Read::read(&mut stream, &mut buf);
    Ok(())
}

pub fn send_control_with_response(line: String) -> io::Result<String> {
    let home = env::var("USERPROFILE").or_else(|_| env::var("HOME")).unwrap_or_default();
    let mut target = env::var("PSMUX_TARGET_SESSION").ok().unwrap_or_else(|| "default".to_string());
    // Never target a warm (standby) session — resolve to a real session instead
    if is_warm_session(&target) {
        let ns = target.strip_suffix("____warm__").map(|s| s.to_string());
        target = resolve_last_session_name_ns(ns.as_deref()).unwrap_or_else(|| "default".to_string());
    }
    let full_target = env::var("PSMUX_TARGET_FULL").ok();
    let path = format!("{}\\.psmux\\{}.port", home, target);
    let port = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse::<u16>().ok()).ok_or_else(|| io::Error::new(io::ErrorKind::Other, format!("no server running on session '{}'", target)))?.clone();
    let session_key = read_session_key(&target).unwrap_or_default();
    let addr = format!("127.0.0.1:{}", port);
    let mut stream = std::net::TcpStream::connect(&addr)?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
    let _ = write!(stream, "AUTH {}\n", session_key);
    if let Some(ref ft) = full_target {
        let _ = write!(stream, "TARGET {}\n", ft);
    }
    let _ = write!(stream, "{}", line);
    let _ = stream.flush();
    let mut buf = Vec::new();
    let mut temp = [0u8; 4096];
    loop {
        match std::io::Read::read(&mut stream, &mut temp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&temp[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    let result = String::from_utf8_lossy(&buf).to_string();
    // Strip the "OK\n" AUTH response prefix if present
    let result = if result.starts_with("OK\n") {
        result[3..].to_string()
    } else if result.starts_with("OK\r\n") {
        result[4..].to_string()
    } else {
        result
    };
    Ok(result)
}

/// Send a control message to a specific port with authentication
pub fn send_control_to_port(port: u16, msg: &str, session_key: &str) -> io::Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    if let Ok(mut stream) = std::net::TcpStream::connect(&addr) {
        let _ = stream.set_nodelay(true);
        let _ = write!(stream, "AUTH {}\n", session_key);
        let _ = stream.write_all(msg.as_bytes());
        let _ = stream.flush();
        // Drain the OK response to prevent RST
        let mut buf = [0u8; 64];
        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
        let _ = std::io::Read::read(&mut stream, &mut buf);
    }
    Ok(())
}

pub fn resolve_last_session_name() -> Option<String> {
    resolve_last_session_name_ns(None)
}

/// Resolve the most recently modified session, optionally filtered by -L namespace.
/// When `ns` is Some("foo"), only sessions with port files named "foo__*" are considered
/// and the returned name includes the prefix (e.g. "foo__dev").
/// When `ns` is None, only non-namespaced sessions (no "__" in name) are considered.
pub fn resolve_last_session_name_ns(ns: Option<&str>) -> Option<String> {
    let home = env::var("USERPROFILE").or_else(|_| env::var("HOME")).ok()?;
    let dir = format!("{}\\.psmux", home);
    let last = std::fs::read_to_string(format!("{}\\last_session", dir)).ok();
    if let Some(name) = last {
        let name = name.trim().to_string();
        // Only accept the cached last_session if it matches the namespace filter
        let ns_ok = match ns {
            Some(n) => name.starts_with(&format!("{}__", n)),
            None => !name.contains("__"),
        };
        if ns_ok {
            let p = format!("{}\\{}.port", dir, name);
            if std::path::Path::new(&p).exists() { return Some(name); }
        }
    }
    let mut picks: Vec<(String, std::time::SystemTime)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if let Some(fname) = e.file_name().to_str() {
                if let Some((base, ext)) = fname.rsplit_once('.') {
                    if ext == "port" { if let Ok(md) = e.metadata() { picks.push((base.to_string(), md.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))); } }
                }
            }
        }
    }
    // Exclude warm (standby) sessions
    picks.retain(|(n, _)| !is_warm_session(n));
    // Filter by namespace: -L sessions have "ns__name" format
    picks.retain(|(n, _)| match ns {
        Some(prefix) => n.starts_with(&format!("{}__", prefix)),
        None => !n.contains("__"),
    });
    picks.sort_by_key(|(_, t)| *t);
    picks.last().map(|(n, _)| n.clone())
}

pub fn resolve_default_session_name() -> Option<String> {
    if let Ok(name) = env::var("PSMUX_DEFAULT_SESSION") {
        let home = env::var("USERPROFILE").or_else(|_| env::var("HOME")).ok()?;
        let p = format!("{}\\.psmux\\{}.port", home, name);
        if std::path::Path::new(&p).exists() { return Some(name); }
    }
    let home = env::var("USERPROFILE").or_else(|_| env::var("HOME")).ok()?;
    let candidates = [format!("{}\\.psmuxrc", home), format!("{}\\.psmux\\pmuxrc", home)];
    for cfg in candidates.iter() {
        if let Ok(text) = std::fs::read_to_string(cfg) {
            let line = text.lines().find(|l| !l.trim().is_empty())?;
            let name = if let Some(rest) = line.strip_prefix("default-session ") { rest.trim().to_string() } else { line.trim().to_string() };
            let p = format!("{}\\.psmux\\{}.port", home, name);
            if std::path::Path::new(&p).exists() { return Some(name); }
        }
    }
    None
}

pub fn resolve_session_target(target: &str, ns: Option<&str>, fallback: Option<&str>) -> Option<String> {
    if target.starts_with('$') {
        return fallback
            .map(|s| s.to_string())
            .or_else(|| resolve_last_session_name_ns(ns));
    }
    Some(match ns {
        Some(prefix) => format!("{}__{}", prefix, target),
        None => target.to_string(),
    })
}

pub fn reap_children_placeholder() -> io::Result<bool> { Ok(false) }

/// Return the names of all live sessions by scanning .psmux/*.port files.
pub fn list_session_names() -> Vec<String> {
    list_session_names_ns(None)
}

/// Return session names filtered by namespace (same logic as resolve_last_session_name_ns).
pub fn list_session_names_ns(ns: Option<&str>) -> Vec<String> {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default();
    let dir = format!("{}\\.psmux", home);
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if let Some(fname) = e.file_name().to_str().map(|s| s.to_string()) {
                if let Some((base, ext)) = fname.rsplit_once('.') {
                    if ext == "port" {
                        if is_warm_session(base) { continue; }
                        // Filter by namespace
                        match ns {
                            Some(prefix) => {
                                if !base.starts_with(&format!("{}__", prefix)) { continue; }
                            }
                            None => {
                                if base.contains("__") { continue; }
                            }
                        }
                        names.push(base.to_string());
                    }
                }
            }
        }
    }
    names.sort();
    names
}

/// A tree entry used by choose-tree: either a session header or a window under a session.
#[derive(Clone, Debug)]
pub struct TreeEntry {
    pub session_name: String,
    pub session_port: u16,
    pub is_session_header: bool,
    pub window_index: Option<usize>,
    pub window_name: String,
    pub window_panes: usize,
    pub window_size: String,
    pub is_current_session: bool,
    pub is_active_window: bool,
}

/// List all running sessions and their windows for choose-tree display.
/// Queries each running server via its TCP port for window list info.
pub fn list_all_sessions_tree(current_session: &str, current_windows: &[(String, usize, String, bool)]) -> Vec<TreeEntry> {
    let home = match env::var("USERPROFILE").or_else(|_| env::var("HOME")) {
        Ok(h) => h,
        Err(_) => return vec![],
    };
    let psmux_dir = format!("{}\\.psmux", home);
    let mut sessions: Vec<(String, u16, std::time::SystemTime)> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&psmux_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "port").unwrap_or(false) {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    // Hide warm (standby) sessions from choose-tree
                    if is_warm_session(stem) { continue; }
                    if let Ok(port_str) = std::fs::read_to_string(&path) {
                        if let Ok(port) = port_str.trim().parse::<u16>() {
                            let mtime = entry.metadata()
                                .and_then(|m| m.modified())
                                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                            sessions.push((stem.to_string(), port, mtime));
                        }
                    }
                }
            }
        }
    }

    sessions.sort_by_key(|(name, _, _)| name.clone());

    let mut tree = Vec::new();
    for (name, port, _) in &sessions {
        let is_current = name == current_session;
        // Session header
        tree.push(TreeEntry {
            session_name: name.clone(),
            session_port: *port,
            is_session_header: true,
            window_index: None,
            window_name: String::new(),
            window_panes: 0,
            window_size: String::new(),
            is_current_session: is_current,
            is_active_window: false,
        });

        if is_current {
            // Use local data for the current session (fast, no IPC)
            for (i, (wname, panes, size, is_active)) in current_windows.iter().enumerate() {
                tree.push(TreeEntry {
                    session_name: name.clone(),
                    session_port: *port,
                    is_session_header: false,
                    window_index: Some(i),
                    window_name: wname.clone(),
                    window_panes: *panes,
                    window_size: size.clone(),
                    is_current_session: true,
                    is_active_window: *is_active,
                });
            }
        } else {
            // Query remote session for its window list
            let key = read_session_key(name).unwrap_or_default();
            let addr = format!("127.0.0.1:{}", port);
            if let Ok(resp) = send_auth_cmd_response(&addr, &key, b"list-windows -F \"#{window_index}:#{window_name}:#{window_panes}:#{window_width}x#{window_height}:#{window_active}\"\n") {
                for line in resp.lines() {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    let parts: Vec<&str> = line.splitn(5, ':').collect();
                    if parts.len() >= 5 {
                        let wi = parts[0].parse::<usize>().unwrap_or(0);
                        let wn = parts[1].to_string();
                        let wp = parts[2].parse::<usize>().unwrap_or(1);
                        let ws = parts[3].to_string();
                        let wa = parts[4] == "1";
                        tree.push(TreeEntry {
                            session_name: name.clone(),
                            session_port: *port,
                            is_session_header: false,
                            window_index: Some(wi),
                            window_name: wn,
                            window_panes: wp,
                            window_size: ws,
                            is_current_session: false,
                            is_active_window: wa,
                        });
                    }
                }
            }
        }
    }
    tree
}

/// Force-kill any remaining psmux/pmux/tmux server processes that didn't
/// exit via the TCP kill-server command.  This is the nuclear fallback that
/// guarantees kill-server always succeeds.
///
/// On Windows, uses CreateToolhelp32Snapshot to enumerate processes and
/// TerminateProcess to kill them.  Skips the current process.
#[cfg(windows)]
pub fn kill_remaining_server_processes() {
    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const INVALID_HANDLE: isize = -1;

    #[repr(C)]
    struct PROCESSENTRY32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> isize;
        fn Process32FirstW(h_snapshot: isize, lppe: *mut PROCESSENTRY32W) -> i32;
        fn Process32NextW(h_snapshot: isize, lppe: *mut PROCESSENTRY32W) -> i32;
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
        fn TerminateProcess(h_process: isize, exit_code: u32) -> i32;
        fn CloseHandle(handle: isize) -> i32;
    }

    let my_pid = std::process::id();

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE || snap == 0 { return; }

        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dw_size = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let target_names: &[&str] = &["psmux.exe", "pmux.exe", "tmux.exe"];
        let mut pids_to_kill: Vec<u32> = Vec::new();

        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                let pid = pe.th32_process_id;
                if pid != my_pid {
                    // Extract exe name from wide string
                    let len = pe.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(260);
                    let name = String::from_utf16_lossy(&pe.sz_exe_file[..len]);
                    let name_lower = name.to_lowercase();
                    for target in target_names {
                        if name_lower == *target || name_lower.ends_with(&format!("\\{}", target)) {
                            pids_to_kill.push(pid);
                            break;
                        }
                    }
                }
                if Process32NextW(snap, &mut pe) == 0 { break; }
            }
        }
        CloseHandle(snap);

        for pid in &pids_to_kill {
            let h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, 0, *pid);
            if h != 0 && h != INVALID_HANDLE {
                let _ = TerminateProcess(h, 1);
                CloseHandle(h);
            }
        }
    }
}

#[cfg(not(windows))]
pub fn kill_remaining_server_processes() {
    // On non-Windows, use signal-based killing
    let _ = std::process::Command::new("pkill")
        .args(&["-f", "psmux|pmux"])
        .status();
}

#[cfg(test)]
#[path = "../tests-rs/test_session.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests-rs/test_issue250_root_cause.rs"]
mod tests_issue250_root_cause;
