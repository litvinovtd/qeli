use super::*;
use std::{path::PathBuf, sync::Arc, time::Duration};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "qeli-tool-probe-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn program(&self, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = self.0.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.to_str().unwrap().to_string()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
async fn wait_file(path: &std::path::Path) {
    tokio::time::timeout(Duration::from_secs(3), async {
        // Creation precedes the shell write; wait for contents before parsing its PID.
        while std::fs::read_to_string(path).map_or(true, |text| text.trim().is_empty()) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn output_status_spawn_and_expiry_are_distinguished() {
    let f = Fixture::new();
    let slots = Semaphore::new(1);
    let good = f.program(
        "good",
        "test \"$#\" = 1 && test \"$1\" = --version && printf version",
    );
    assert_eq!(probe(&slots, &good, deadline()).await.unwrap(), Some(good));
    let missing = f.0.join("missing").to_str().unwrap().to_owned();
    assert!(probe(&slots, &missing, deadline()).await.unwrap().is_none());
    let fail = f.program("fail", "exit 17");
    let error = probe(&slots, &fail, deadline()).await.unwrap_err();
    assert!(error.to_string().contains("17"));
    let flood = f.program("flood", "head -c 65537 /dev/zero");
    assert_eq!(
        probe(&slots, &flood, deadline()).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        find_async(Tool::Ipv6, Instant::now())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(slots.available_permits(), 1);
}

#[tokio::test]
async fn expired_or_queued_probe_never_spawns() {
    let f = Fixture::new();
    let marker = f.0.join("started");
    let command = f.program("probe", &format!("touch '{}'", marker.display()));
    for permits in [0, 1] {
        let slots = Semaphore::new(permits);
        let until = if permits == 0 {
            Instant::now() + Duration::from_millis(25)
        } else {
            Instant::now()
        };
        assert_eq!(
            probe(&slots, &command, until).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!marker.exists());
    }
}

#[tokio::test]
async fn queue_wait_consumes_command_budget() {
    let f = Fixture::new();
    let command = f.program("slow", "sleep 0.40; printf late-success");
    let slots = Arc::new(Semaphore::new(1));
    let held = slots.clone().acquire_owned().await.unwrap();
    let until = Instant::now() + Duration::from_millis(500);
    let release = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(held);
    };
    let (result, ()) = tokio::join!(probe(&slots, &command, until), release);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(slots.available_permits(), 1);
}

#[tokio::test]
async fn parallel_requests_are_admitted_only_up_to_the_slot_limit() {
    let f = Fixture::new();
    let started = f.0.join("started");
    let release = f.0.join("release");
    let command = f.program("limited", &format!(
        "echo $$ >> '{}'\ni=0\nwhile [ ! -e '{}' ] && [ $i -lt 300 ]; do sleep 0.01; i=$((i+1)); done\ntest -e '{}'",
        started.display(), release.display(), release.display(),
    ));
    let slots = Arc::new(Semaphore::new(4));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (slots, command) = (slots.clone(), command.clone());
        tasks.push(tokio::spawn(async move {
            probe(&slots, &command, deadline()).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while std::fs::read_to_string(&started)
            .unwrap_or_default()
            .lines()
            .count()
            < 4
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        std::fs::read_to_string(&started).unwrap().lines().count(),
        4
    );
    assert_eq!(slots.available_permits(), 0);
    std::fs::write(&release, b"release").unwrap();
    for task in tasks {
        assert!(task.await.unwrap().unwrap().is_some());
    }
    assert_eq!(
        std::fs::read_to_string(&started).unwrap().lines().count(),
        8
    );
    assert_eq!(slots.available_permits(), 4);
}

#[tokio::test]
async fn cancelling_a_running_probe_kills_the_child_and_releases_its_slot() {
    let f = Fixture::new();
    let started = f.0.join("pid");
    let command = f.program(
        "cancel",
        &format!("echo $$ > '{}'; exec sleep 30", started.display()),
    );
    let slots = Arc::new(Semaphore::new(1));
    let used = slots.clone();
    let task = tokio::spawn(async move { probe(&used, &command, deadline()).await });
    wait_file(&started).await;
    let pid: u32 = std::fs::read_to_string(started)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(slots.available_permits(), 1);
    tokio::time::timeout(Duration::from_secs(3), async {
        while std::path::Path::new(&format!("/proc/{pid}")).exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled probe was not reaped");
}

#[tokio::test]
async fn task_local_probe_selection_does_not_cross_requests_or_families() {
    let f = Fixture::new();
    let yes = f.program("yes", "printf present");
    let no = f.0.join("absent").to_str().unwrap().to_owned();
    let (v4, v6) = tokio::join!(
        with_probe(yes.clone(), find_async(Tool::Ipv4, deadline())),
        with_probe(no, find_async(Tool::Ipv6, deadline())),
    );
    assert_eq!(v4.unwrap(), Some(yes));
    assert!(v6.unwrap().is_none());
}
