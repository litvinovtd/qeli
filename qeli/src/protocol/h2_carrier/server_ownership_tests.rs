use super::test_support::*;
use super::*;
use crate::profile_tasks::ProfileTasks;
use std::sync::atomic::Ordering;

async fn accept_profile<S>(
    io: S,
    owner: &crate::profile_tasks::ProfileSpawner,
) -> io::Result<Carrier>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    accept_owned(io, owner, ())
        .await
        .map(|(carrier, ())| carrier)
}

fn request(method: Method, path: &str) -> Request<()> {
    Request::builder()
        .method(method)
        .uri(format!("https://example.com{path}"))
        .header("content-type", GRPC_MEDIA_TYPE)
        .header("te", "trailers")
        .body(())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_shutdown_joins_h2_before_return_and_allows_retry() {
    let (mut io, peer, released) = observed_pair();
    let (release, dropping) = hold_drop(&mut io);
    let tasks = ProfileTasks::new("h2-test");
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_profile(io, &owner).await.unwrap() });
    let client = connect(peer, "example.com").await.unwrap();
    let server = server.await.unwrap();
    assert!(tasks.spawn(async move {
        let _server = server;
        std::future::pending::<()>().await;
    }));
    assert!(tokio::time::timeout(PROBE, async {
        let (first, second) = tokio::join!(tasks.shutdown(), tasks.shutdown());
        first.unwrap();
        second.unwrap();
    })
    .await
    .is_err());
    tokio::time::timeout(DEADLINE, dropping)
        .await
        .unwrap()
        .unwrap();
    assert!(!released.load(Ordering::Acquire));
    drop(release);
    tokio::time::timeout(DEADLINE, tasks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(released.load(Ordering::Acquire));
    drop(client);
}

#[tokio::test]
async fn cancelled_accept_releases_io_before_preface_or_first_request() {
    for preface_sent in [false, true] {
        let (io, peer, released) = observed_pair();
        let tasks = ProfileTasks::new("pending-h2");
        let owner = tasks.spawner();
        let mut send_request = None;
        let mut driver = None;
        let mut idle_peer = Some(peer);
        if preface_sent {
            let (sender, connection) = configure_client()
                .handshake::<_, Bytes>(idle_peer.take().unwrap())
                .await
                .unwrap();
            send_request = Some(sender);
            driver = Some(tokio::spawn(connection));
        }
        let mut accepting = Box::pin(accept_profile(io, &owner));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(accepting.as_mut(), cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(accepting);
        tasks.shutdown().await.unwrap();
        assert!(released.load(Ordering::Acquire));
        if let Some(driver) = driver {
            driver.abort();
            let _ = driver.await;
        }
        drop(send_request);
        drop(idle_peer);
    }
}

#[tokio::test]
async fn closed_profile_rejects_h2_driver_and_releases_io() {
    let (io, peer, released) = observed_pair();
    let tasks = ProfileTasks::new("closed-h2");
    tasks.shutdown().await.unwrap();
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_profile(io, &owner).await });
    let client = tokio::time::timeout(DEADLINE, connect(peer, "example.com"))
        .await
        .unwrap();
    assert!(client.is_err());
    let error = server.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(released.load(Ordering::Acquire));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejection_delivers_status_and_profile_joins_flush() {
    let (mut io, peer, released) = observed_pair();
    let (release, dropping) = hold_drop(&mut io);
    let tasks = ProfileTasks::new("rejected-h2");
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_profile(io, &owner).await });
    let (send, connection) = configure_client()
        .handshake::<_, Bytes>(peer)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut send = send.ready().await.unwrap();
    let (response, _body) = send
        .send_request(request(Method::GET, CARRIER_PATH), true)
        .unwrap();
    assert_eq!(
        tokio::time::timeout(DEADLINE, response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        server.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(tokio::time::timeout(PROBE, tasks.shutdown()).await.is_err());
    tokio::time::timeout(DEADLINE, dropping)
        .await
        .unwrap()
        .unwrap();
    assert!(!released.load(Ordering::Acquire));
    drop(release);
    tokio::time::timeout(DEADLINE, tasks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(released.load(Ordering::Acquire));
    driver.abort();
    let _ = driver.await;
}

#[tokio::test]
async fn rejection_flush_expires_without_peer_close_or_profile_shutdown() {
    let (io, peer, released) = observed_pair();
    let tasks = ProfileTasks::new("bounded-rejection");
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_profile(io, &owner).await });
    let (send, connection) = configure_client()
        .handshake::<_, Bytes>(peer)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut send = send.ready().await.unwrap();
    let (response, _body) = send
        .send_request(request(Method::GET, CARRIER_PATH), true)
        .unwrap();
    assert_eq!(
        tokio::time::timeout(DEADLINE, response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert!(server.await.unwrap().is_err());
    tokio::time::timeout(DEADLINE, async {
        while !released.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tasks.spawn(async {}),
        "flush expiry must not close the profile"
    );
    tasks.shutdown().await.unwrap();
    driver.abort();
    let _ = driver.await;
}

#[tokio::test]
async fn profile_shutdown_stops_backpressured_server_bridge() {
    let (io, peer, released) = observed_pair();
    let tasks = ProfileTasks::new("blocked-h2");
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_profile(io, &owner).await.unwrap() });
    let mut builder = configure_client();
    builder.initial_window_size(0);
    let (send, connection) = builder.handshake::<_, Bytes>(peer).await.unwrap();
    let driver = tokio::spawn(connection);
    let mut send = send.ready().await.unwrap();
    let (response, _body) = send
        .send_request(request(Method::POST, CARRIER_PATH), false)
        .unwrap();
    let _response = response.await.unwrap();
    let mut server = server.await.unwrap();
    let (filled, ready) = tokio::sync::oneshot::channel();
    let (done, mut finished) = tokio::sync::oneshot::channel();
    assert!(tasks.spawn(async move {
        let payload = vec![42; BRIDGE_CAPACITY];
        server.write_all(&payload).await.unwrap();
        filled.send(()).unwrap();
        let _ = server.write_all(&payload).await;
        let _ = done.send(());
    }));
    tokio::time::timeout(DEADLINE, ready)
        .await
        .unwrap()
        .unwrap();
    assert!(tokio::time::timeout(PROBE, &mut finished).await.is_err());
    tokio::time::timeout(DEADLINE, tasks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(released.load(Ordering::Acquire));
    driver.abort();
    let _ = driver.await;
}

#[tokio::test]
async fn profile_owned_half_close_keeps_reverse_reply() {
    let (io, peer, released) = observed_pair();
    let tasks = ProfileTasks::new("half-close-h2");
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_profile(io, &owner).await.unwrap() });
    let mut client = connect(peer, "example.com").await.unwrap();
    let mut server = server.await.unwrap();
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();
    let mut request = Vec::new();
    tokio::time::timeout(DEADLINE, server.read_to_end(&mut request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request, b"request");
    server.write_all(b"reply").await.unwrap();
    server.shutdown().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(DEADLINE, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"reply");
    tasks.shutdown().await.unwrap();
    assert!(released.load(Ordering::Acquire));
    drop(server);
    drop(client);
}

#[tokio::test]
async fn profile_driver_preserves_later_stream_not_found() {
    let (io, peer, released) = observed_pair();
    let tasks = ProfileTasks::new("later-stream-h2");
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_profile(io, &owner).await.unwrap() });
    let (send, connection) = configure_client()
        .handshake::<_, Bytes>(peer)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut send = send.ready().await.unwrap();
    let (response, _first_body) = send
        .send_request(request(Method::POST, CARRIER_PATH), false)
        .unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    let server = server.await.unwrap();
    send = send.ready().await.unwrap();
    let (response, _second_body) = send
        .send_request(request(Method::POST, "/another"), true)
        .unwrap();
    assert_eq!(
        tokio::time::timeout(DEADLINE, response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    tasks.shutdown().await.unwrap();
    assert!(released.load(Ordering::Acquire));
    drop(server);
    driver.abort();
    let _ = driver.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejection_retains_pre_auth_slot_until_io_destruction() {
    let (mut io, peer, released) = observed_pair();
    let (release, dropping) = hold_drop(&mut io);
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let tasks = ProfileTasks::new("rejection-admission");
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_owned(io, &owner, permit).await });
    let (send, connection) = configure_client()
        .handshake::<_, Bytes>(peer)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut send = send.ready().await.unwrap();
    let (response, _body) = send
        .send_request(request(Method::GET, CARRIER_PATH), true)
        .unwrap();
    assert_eq!(
        tokio::time::timeout(DEADLINE, response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert!(server.await.unwrap().is_err());
    assert_eq!(
        slots.available_permits(),
        0,
        "live rejection socket must retain admission"
    );
    assert!(tokio::time::timeout(PROBE, tasks.shutdown()).await.is_err());
    tokio::time::timeout(DEADLINE, dropping)
        .await
        .unwrap()
        .unwrap();
    assert!(!released.load(Ordering::Acquire));
    assert_eq!(
        slots.available_permits(),
        0,
        "I/O destructor must finish before releasing admission"
    );
    drop(release);
    tokio::time::timeout(DEADLINE, tasks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(released.load(Ordering::Acquire));
    assert_eq!(slots.available_permits(), 1);
    driver.abort();
    let _ = driver.await;
}

#[tokio::test]
async fn accepted_carrier_hands_admission_to_inner_authentication() {
    let (io, peer, released) = observed_pair();
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let tasks = ProfileTasks::new("accepted-admission");
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_owned(io, &owner, permit).await.unwrap() });
    let client = connect(peer, "example.com").await.unwrap();
    let (server, permit) = server.await.unwrap();
    assert_eq!(slots.available_permits(), 0);
    // Match handle_client's successful inner AUTH boundary, not the H2 200 response.
    drop(permit);
    assert_eq!(slots.available_permits(), 1);
    assert!(!released.load(Ordering::Acquire));
    tasks.shutdown().await.unwrap();
    assert!(released.load(Ordering::Acquire));
    drop(server);
    drop(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_unpolled_flush_drops_io_before_admission() {
    let (mut io, peer, released) = observed_pair();
    let (release, dropping) = hold_drop(&mut io);
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let tasks = ProfileTasks::new("closed-admission");
    tasks.shutdown().await.unwrap();
    let owner = tasks.spawner();
    let server = tokio::spawn(async move { accept_owned(io, &owner, permit).await });
    let (send, connection) = configure_client()
        .handshake::<_, Bytes>(peer)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut send = send.ready().await.unwrap();
    let (_response, _body) = send
        .send_request(request(Method::GET, CARRIER_PATH), true)
        .unwrap();
    tokio::time::timeout(DEADLINE, dropping)
        .await
        .unwrap()
        .unwrap();
    assert!(!released.load(Ordering::Acquire));
    assert_eq!(slots.available_permits(), 0);
    drop(release);
    assert_eq!(
        tokio::time::timeout(DEADLINE, server)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert!(released.load(Ordering::Acquire));
    assert_eq!(slots.available_permits(), 1);
    driver.abort();
    let _ = driver.await;
}
