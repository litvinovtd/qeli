use super::*;

#[test]
fn missing_tool_is_distinct_from_an_unverified_probe() {
    assert!(warning(Ok(Some("/sbin/iptables".into()))).is_none());
    assert_eq!(warning(Ok(None)).unwrap().severity, "critical");
    for kind in [
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::InvalidData,
    ] {
        let observed = warning(Err(std::io::Error::new(kind, "fixture error"))).unwrap();
        assert_eq!(observed.severity, "warning");
        assert!(observed.message.contains("Could not verify"));
        assert!(!observed.message.contains("not installed"));
    }
}

#[tokio::test]
async fn no_nat_does_not_probe_the_firewall_tool() {
    let config = ServerConfig {
        profiles: vec![],
        ..Default::default()
    };
    let observed = crate::server::nat::with_probe(
        "/qeli-fixture-tool-does-not-exist".into(),
        nat_warning(&config),
    )
    .await;
    assert!(observed.is_none());
}

#[test]
#[ignore = "requires Linux root/CAP_SYS_ADMIN for private mount/network namespaces; in-process HTTP router"]
fn native_health_probe_keeps_neighboring_http_requests_responsive() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::{os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};
    use tower::ServiceExt;

    assert!(
        std::env::var_os("QELI_CONTROL_SOCKET").is_none(),
        "fixture requires the default socket under private /run"
    );
    let root = std::env::temp_dir().join(format!(
        "qeli-health-probe-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    std::thread::spawn(move || {
        // SAFETY: only this disposable thread changes namespaces; /run is hidden before API calls.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET) }, 0);
        for args in [vec!["--make-rprivate", "/"], vec!["-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run"]] {
            assert!(crate::system_command::Command::new("mount").args(args).output().unwrap().status.success());
        }
        assert!(!std::path::Path::new(&crate::server::control::control_socket_path()).exists());
        let raw = "[auth]\nusers_file=/unused-fixture/users.conf\n[web]\nenabled=false\ntls=false\ninsecure_no_auth=true\n[profile:probe]\nidentity_key=/unused-fixture/key\nbind.port=443\ntun.name=vpn0\ntun.address=10.73.0.1\npool.cidr=10.73.0.0/24\nrouting.nat.enabled=true\nobf.mode=fake-tls\n";
        let config_path = root.join("server.conf");
        std::fs::write(&config_path, raw).unwrap();
        let config = crate::config::parse_server_config(raw).unwrap();
        let state = crate::server::test_api_state(config, &config_path);
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let app = crate::server::web::api::routes().with_state(state);
            for (number, endpoint) in ["/status", "/transport/health"].into_iter().enumerate() {
                let started = root.join(format!("started-{number}"));
                let program = root.join(format!("iptables-{number}"));
                std::fs::write(&program, format!("#!/bin/sh\ntouch '{}'\nsleep 1.5\nprintf fixture-version\n", started.display())).unwrap();
                std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
                let request = Request::builder().uri(endpoint).body(Body::empty()).unwrap();
                let slow = tokio::spawn(crate::server::nat::with_probe(
                    program.to_str().unwrap().to_owned(), app.clone().oneshot(request),
                ));
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !started.exists() { tokio::time::sleep(Duration::from_millis(5)).await; }
                }).await.unwrap();
                assert!(!slow.is_finished(), "{endpoint} blocked the current-thread executor until the child exited");
                let neighbor = tokio::time::timeout(Duration::from_millis(300),
                    app.clone().oneshot(Request::builder().uri("/system").body(Body::empty()).unwrap()),
                ).await.expect("neighboring HTTP request was blocked").unwrap();
                assert_eq!(neighbor.status(), StatusCode::OK);
                assert!(!slow.is_finished(), "probe completed before neighbor request; fixture did not overlap");
                let response = slow.await.unwrap().unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
                let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert!(!value.to_string().contains("Could not verify iptables"));
                assert!(!value.to_string().contains("iptables` is not installed"));
            }
        });
    }).join().expect("isolated HTTP probe test panicked");
}
