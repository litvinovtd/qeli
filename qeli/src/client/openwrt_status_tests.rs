use super::*;

fn reporter() -> (
    ClientStatusReporter,
    status_writer::Writer<serde_json::Value>,
    std::sync::mpsc::Receiver<serde_json::Value>,
) {
    let (tx, rx) = std::sync::mpsc::channel();
    let (sender, writer) = status_writer::Writer::start(move |value| {
        tx.send(value).unwrap();
    })
    .unwrap();
    (
        ClientStatusReporter {
            sender: Some(sender),
            state: Arc::new(std::sync::Mutex::new(ClientDiagnosticState {
                profile: "secret-profile".into(),
                state: "created".into(),
                generation: 0,
                reconnects: 0,
                retry_in_secs: None,
                last_error: None,
                plan: None,
                last_error_code: None,
                retry_until: None,
                tcp_live: None,
                tun_ifindex: None,
                terminal: false,
            })),
            identity: status_writer::ProcessIdentity::current(),
            device: "qeli0".into(),
            openwrt: true,
        },
        writer,
        rx,
    )
}

fn sample(
    reporter: &ClientStatusReporter,
    rx: &std::sync::mpsc::Receiver<serde_json::Value>,
) -> serde_json::Value {
    reporter.publish(&RuntimeCounters::default());
    rx.recv_timeout(Duration::from_secs(2)).unwrap()
}

#[test]
fn openwrt_status_tracks_ready_retry_and_terminal_without_free_form_secrets() {
    let (reporter, _writer, rx) = reporter();
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "connecting");
    reporter.update_state(ClientState::AwaitingNetwork, 0);
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "connecting");
    reporter.update_state(ClientState::Running, 0);
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "connected");
    let error = anyhow::anyhow!("password=secret qeli://private-key");
    reporter.retrying(Some(&error), 1, 60);
    let value = sample(&reporter, &rx);
    assert_eq!(value["tunnel"]["state"], "reconnecting");
    assert_eq!(value["tunnel"]["last_error_code"], "connection_failed");
    assert!((59..=60).contains(&value["tunnel"]["retry_in_secs"].as_u64().unwrap()));
    assert!(!value.to_string().contains("secret"));
    assert!(!value.to_string().contains("qeli://"));
    reporter.update_state(ClientState::Connecting, 1);
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "reconnecting");
    // Core Stopped closes one attempt; only the outer owner decides that retries
    // have finished. Cleanup between attempts must not show a terminal state.
    reporter.update_state(ClientState::Stopped, 1);
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "reconnecting");
    reporter.update_state(ClientState::Failed, 1);
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "reconnecting");
    reporter.terminal(Some(&error));
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "error");
    reporter.terminal(None);
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "stopped");
}

#[test]
fn openwrt_status_marks_zero_tcp_paths_reconnecting_during_resume_grace() {
    let (reporter, _writer, rx) = reporter();
    reporter.update_state(ClientState::Running, 0);
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(1));
    reporter.state.lock().unwrap().tcp_live = Some(live.clone());
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "connected");
    live.store(0, Ordering::Release);
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "reconnecting");
    live.store(1, Ordering::Release);
    assert_eq!(sample(&reporter, &rx)["tunnel"]["state"], "connected");
}

#[test]
fn openwrt_status_identity_and_clock_are_process_scoped() {
    let identity = status_writer::ProcessIdentity::current().unwrap();
    let a = identity.snapshot();
    let b = identity.snapshot();
    assert_eq!(a["pid"], std::process::id());
    assert_eq!(a["run_id"], b["run_id"]);
    assert!(
        b["updated_boottime_ms"].as_u64().unwrap() >= a["updated_boottime_ms"].as_u64().unwrap()
    );
    let uptime: f64 = std::fs::read_to_string("/proc/uptime")
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!((uptime * 1000.0 - b["updated_boottime_ms"].as_u64().unwrap() as f64).abs() < 1000.0);
}
