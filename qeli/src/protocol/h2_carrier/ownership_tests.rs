use super::test_support::*;
use super::*;
use crate::transport_core::tasks::TaskGroup;
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generation_join_waits_for_nested_h2_transport_destruction() {
    let (mut io, peer, released) = observed_pair();
    let (release, dropping) = hold_drop(&mut io);
    let server = tokio::spawn(async move { accept(peer).await.unwrap() });
    let mut group = TaskGroup::default();
    let client = connect_owned(io, "example.com", &group.spawner())
        .await
        .unwrap();
    let server = server.await.unwrap();
    assert!(group.spawner().spawn(async move {
        let _client = client;
        std::future::pending::<()>().await;
    }));
    // Cancelling and retrying the finish waiter must retain ALL join handles.
    assert!(tokio::time::timeout(PROBE, group.finish()).await.is_err());
    tokio::time::timeout(DEADLINE, dropping)
        .await
        .unwrap()
        .unwrap();
    assert!(!released.load(Ordering::Acquire));
    drop(release);
    tokio::time::timeout(DEADLINE, group.finish())
        .await
        .unwrap();
    assert!(released.load(Ordering::Acquire));
    drop(server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_pending_connect_keeps_driver_joinable() {
    let (mut io, peer, released) = observed_pair();
    let (release, dropping) = hold_drop(&mut io);
    let (seen, request_seen) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = configure_server()
            .handshake::<_, Bytes>(peer)
            .await
            .unwrap();
        let _request = connection.accept().await.unwrap().unwrap();
        seen.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let mut group = TaskGroup::default();
    let spawner = group.spawner();
    let mut attempt = Box::pin(spawner.scope(connect_owned(io, "example.com", &spawner)));
    tokio::select! {
        result = &mut attempt => panic!("unexpected response: {result:?}"),
        seen = tokio::time::timeout(DEADLINE, request_seen) => seen.unwrap().unwrap(),
    }
    drop(attempt);
    tokio::time::timeout(DEADLINE, dropping)
        .await
        .unwrap()
        .unwrap();
    assert!(tokio::time::timeout(PROBE, group.finish()).await.is_err());
    assert!(!released.load(Ordering::Acquire));
    drop(release);
    tokio::time::timeout(DEADLINE, group.finish())
        .await
        .unwrap();
    assert!(released.load(Ordering::Acquire));
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn failed_request_build_releases_transport_before_join_returns() {
    let (io, _peer, released) = observed_pair();
    let mut group = TaskGroup::default();
    let result = tokio::time::timeout(
        DEADLINE,
        connect_owned(io, "bad authority", &group.spawner()),
    )
    .await
    .unwrap();
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("request build failed"));
    tokio::time::timeout(DEADLINE, group.finish())
        .await
        .unwrap();
    assert!(released.load(Ordering::Acquire));
}

#[tokio::test]
async fn closed_owner_rejects_connect_and_releases_transport() {
    let (io, _peer, released) = observed_pair();
    let mut group = TaskGroup::default();
    group.finish().await;
    let result = tokio::time::timeout(DEADLINE, connect_owned(io, "example.com", &group.spawner()))
        .await
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert!(released.load(Ordering::Acquire));
}

#[tokio::test]
async fn dropping_owner_stops_workers_even_while_carrier_survives() {
    let (io, peer, released) = observed_pair();
    let server = tokio::spawn(async move { accept(peer).await.unwrap() });
    let group = TaskGroup::default();
    let client = connect_owned(io, "example.com", &group.spawner())
        .await
        .unwrap();
    let server = server.await.unwrap();
    drop(group);
    tokio::time::timeout(DEADLINE, async {
        while !released.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(client);
    drop(server);
}

#[tokio::test]
async fn owned_half_close_keeps_reply_and_end_stream_intact() {
    let (io, peer, released) = observed_pair();
    let server = tokio::spawn(async move { accept(peer).await.unwrap() });
    let mut group = TaskGroup::default();
    let mut client = connect_owned(io, "example.com", &group.spawner())
        .await
        .unwrap();
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
    let mut reply = Vec::new();
    tokio::time::timeout(DEADLINE, client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"reply");
    group.finish().await;
    assert!(released.load(Ordering::Acquire));
    drop(client);
    drop(server);
}

#[tokio::test]
async fn generation_join_stops_bridge_when_peer_window_is_zero() {
    let (io, peer, released) = observed_pair();
    let server = tokio::spawn(async move {
        let mut builder = configure_server();
        builder.initial_window_size(0);
        let mut connection = builder.handshake::<_, Bytes>(peer).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let _body = request.into_body();
        let _response = respond
            .send_response(Response::builder().status(200).body(()).unwrap(), false)
            .unwrap();
        while connection.accept().await.is_some() {}
    });
    let mut group = TaskGroup::default();
    let mut client = connect_owned(io, "example.com", &group.spawner())
        .await
        .unwrap();
    let (filled, ready) = tokio::sync::oneshot::channel();
    let (finished, mut write_finished) = tokio::sync::oneshot::channel();
    assert!(group.spawner().spawn(async move {
        let payload = vec![42; BRIDGE_CAPACITY];
        client.write_all(&payload).await.unwrap();
        filled.send(()).unwrap();
        let _ = client.write_all(&payload).await;
        let _ = finished.send(());
    }));
    tokio::time::timeout(DEADLINE, ready)
        .await
        .unwrap()
        .unwrap();
    assert!(tokio::time::timeout(PROBE, &mut write_finished)
        .await
        .is_err());
    tokio::time::timeout(DEADLINE, group.finish())
        .await
        .unwrap();
    assert!(released.load(Ordering::Acquire));
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn dropping_one_carrier_preserves_another_in_the_same_generation() {
    let mut group = TaskGroup::default();
    let (active_io, active_peer, active_released) = observed_pair();
    let server = tokio::spawn(async move { accept(active_peer).await.unwrap() });
    let mut active = connect_owned(active_io, "example.com", &group.spawner())
        .await
        .unwrap();
    let mut active_server = server.await.unwrap();
    let (candidate_io, candidate_peer, candidate_released) = observed_pair();
    let server = tokio::spawn(async move { accept(candidate_peer).await.unwrap() });
    let candidate = connect_owned(candidate_io, "example.com", &group.spawner())
        .await
        .unwrap();
    let candidate_server = server.await.unwrap();
    drop(candidate);
    tokio::time::timeout(DEADLINE, async {
        while !candidate_released.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!active_released.load(Ordering::Acquire));
    active.write_all(b"still active").await.unwrap();
    let mut received = [0u8; 12];
    tokio::time::timeout(DEADLINE, active_server.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"still active");
    group.finish().await;
    assert!(active_released.load(Ordering::Acquire));
    drop(active);
    drop(active_server);
    drop(candidate_server);
}
