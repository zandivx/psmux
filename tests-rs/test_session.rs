// Tests for crate::session::fetch_session_info, covering the AUTH+session-info
// framing race that motivated issue #250.
//
// Each test spins up a minimal in-process TCP listener on 127.0.0.1:0 that
// acts as a fake psmux session server, then calls the real production
// function — no re-implementation of the parser in the test.

use super::*;

use std::io::{Read, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn tmux_session_id_target_resolves_to_last_session() {
    assert_eq!(resolve_session_target("$0", None, Some("4-pane-split")), Some("4-pane-split".to_string()));
}

#[test]
fn literal_session_target_is_preserved() {
    assert_eq!(resolve_session_target("4-pane-split", None, Some("other")), Some("4-pane-split".to_string()));
}

/// Read the `AUTH <key>\n` + `session-info\n` lines the client sends so the
/// fake server's subsequent writes land against the expected client state.
fn drain_client_request(stream: &mut TcpStream) {
    // AUTH line + session-info line — two LFs total.
    let mut seen_lf = 0u8;
    let mut buf = [0u8; 1];
    while seen_lf < 2 {
        match stream.read(&mut buf) {
            Ok(0) => return,
            Ok(_) => {
                if buf[0] == b'\n' {
                    seen_lf += 1;
                }
            }
            Err(_) => return,
        }
    }
}

/// Spawns a listener bound to an ephemeral port, hands the accepted stream
/// to `respond`, and returns `127.0.0.1:<port>` for the client to dial.
///
/// Returns the address plus a channel the caller can block on to ensure the
/// server thread finished before the test exits.
fn spawn_fake_server<F>(respond: F) -> (String, mpsc::Receiver<()>)
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap().to_string();
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            respond(stream);
        }
        let _ = done_tx.send(());
    });
    (addr, done_rx)
}

#[test]
fn happy_path_returns_info_line() {
    let (addr, done) = spawn_fake_server(|mut s| {
        drain_client_request(&mut s);
        let _ = s.write_all(b"OK\n");
        let _ = s.write_all(b"call-controller: 2 windows (created Mon Apr 20 11:10:58 2026)\n");
        let _ = s.flush();
    });

    let info = fetch_session_info(
        &addr,
        "key",
        Duration::from_millis(200),
        Duration::from_millis(500),
    );

    assert_eq!(
        info.as_deref(),
        Some("call-controller: 2 windows (created Mon Apr 20 11:10:58 2026)")
    );
    let _ = done.recv_timeout(Duration::from_secs(2));
}

#[test]
fn issue_250_late_auth_ack_is_not_reported_as_session_info() {
    // Reproduces the #250 race: AUTH `OK\n` is delayed until after the client's
    // first read_line would have timed out. In the old code the late "OK"
    // landed in the second read and was rendered as the session name. The
    // production function must either return the real info or `None` — never
    // `Some("OK")`.
    let (addr, done) = spawn_fake_server(|mut s| {
        drain_client_request(&mut s);
        // Hold the "OK" ack longer than the client's per-read timeout so the
        // first read_line is forced to return (on the old code, empty) and
        // the ack arrives during what was previously the "info" read.
        thread::sleep(Duration::from_millis(120));
        let _ = s.write_all(b"OK\n");
        let _ = s.flush();
        // Then send the real info line comfortably within the second read.
        thread::sleep(Duration::from_millis(20));
        let _ = s.write_all(b"convserv: 3 windows (created Mon Apr 20 11:11:06 2026)\n");
        let _ = s.flush();
    });

    let info = fetch_session_info(
        &addr,
        "key",
        Duration::from_millis(200),
        Duration::from_millis(80),  // shorter than the 120ms server delay
    );

    // The critical assertion: even under the race, we never mis-report "OK"
    // as the info line. Either the real line makes it (if the read timeout
    // is generous) or we get None — but never Some("OK").
    assert_ne!(info.as_deref(), Some("OK"), "late AUTH ack leaked as session info");
    let _ = done.recv_timeout(Duration::from_secs(2));
}

#[test]
fn only_ok_ack_received_returns_none() {
    // Server replies with just the AUTH ack and never sends session-info
    // (the worst-case of #250: second read's timeout leaves nothing).
    let (addr, done) = spawn_fake_server(|mut s| {
        drain_client_request(&mut s);
        let _ = s.write_all(b"OK\n");
        let _ = s.flush();
        // Keep the connection open briefly so the client isn't racing EOF
        // against its own read_timeout.
        thread::sleep(Duration::from_millis(200));
    });

    let info = fetch_session_info(
        &addr,
        "key",
        Duration::from_millis(200),
        Duration::from_millis(80),
    );

    assert_eq!(info, None, "sole OK ack must not be reported as info");
    let _ = done.recv_timeout(Duration::from_secs(2));
}

#[test]
fn connect_refused_returns_none() {
    // Bind then drop the listener so the port is (briefly) closed — on
    // loopback this produces a fast refusal. The socket might race to be
    // reused, but `fetch_session_info` must never panic and must return
    // None on connect failure.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);

    let info = fetch_session_info(
        &addr,
        "key",
        Duration::from_millis(50),
        Duration::from_millis(50),
    );

    assert_eq!(info, None);
}

#[test]
fn auth_rejected_returns_none() {
    // Server responds to AUTH with an error instead of OK — must not be
    // rendered as the session info line.
    let (addr, done) = spawn_fake_server(|mut s| {
        drain_client_request(&mut s);
        let _ = s.write_all(b"ERROR: Invalid session key\n");
        let _ = s.flush();
    });

    let info = fetch_session_info(
        &addr,
        "wrong-key",
        Duration::from_millis(200),
        Duration::from_millis(200),
    );

    // The picker should fall back to the generic "(not responding)"
    // label rather than rendering the raw ERROR line as the session info.
    assert_eq!(info, None, "auth error leaked as session info: {:?}", info);
    let _ = done.recv_timeout(Duration::from_secs(2));
}
