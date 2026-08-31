use super::*;

fn raw_request(
    method: Method,
    path: &str,
    content_type: Option<&str>,
    te: Option<&str>,
) -> Request<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://example.com{path}"));
    if let Some(value) = content_type {
        builder = builder.header("content-type", value);
    }
    if let Some(value) = te {
        builder = builder.header("te", value);
    }
    builder.body(()).unwrap()
}

async fn rejection(request: Request<()>) -> (String, StatusCode) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        match accept(server_io).await {
            Ok(_) => panic!("invalid carrier request was accepted"),
            Err(error) => error,
        }
    });
    let (send_request, connection) = configure_client()
        .handshake::<_, Bytes>(client_io)
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request.ready().await.unwrap();
    let (response, _) = send_request.send_request(request, true).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(2), response)
        .await
        .expect("HTTP rejection response timed out")
        .unwrap()
        .status();
    let error = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server rejection timed out")
        .unwrap();
    driver.abort();
    (error.to_string(), status)
}

#[tokio::test]
async fn rejects_wrong_method_path_media_type_and_te() {
    let cases = [
        (
            raw_request(
                Method::GET,
                CARRIER_PATH,
                Some(GRPC_MEDIA_TYPE),
                Some("trailers"),
            ),
            "streaming POST",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            raw_request(
                Method::POST,
                "/v1/probe",
                Some(GRPC_MEDIA_TYPE),
                Some("trailers"),
            ),
            "path is not available",
            StatusCode::NOT_FOUND,
        ),
        (
            raw_request(
                Method::POST,
                CARRIER_PATH,
                Some("application/octet-stream"),
                Some("trailers"),
            ),
            "requires gRPC content",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            raw_request(Method::POST, CARRIER_PATH, Some(GRPC_MEDIA_TYPE), None),
            "requires TE trailers",
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (request, expected, expected_status) in cases {
        let (error, status) = rejection(request).await;
        assert!(error.contains(expected), "unexpected rejection: {error}");
        assert_eq!(status, expected_status);
    }
}

#[tokio::test]
async fn accepts_grpc_suffix_and_parameters() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move { accept(server_io).await.unwrap() });
    let (send_request, connection) = configure_client()
        .handshake::<_, Bytes>(client_io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request.ready().await.unwrap();
    let request = raw_request(
        Method::POST,
        CARRIER_PATH,
        Some("application/grpc+proto; charset=utf-8"),
        Some("trailers"),
    );
    let (response, _) = send_request.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    drop(server.await.unwrap());
}

#[tokio::test]
async fn malformed_preface_fails_without_hanging() {
    let (mut client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move { accept(server_io).await });
    client_io.write_all(b"NOT AN HTTP/2 PREFACE").await.unwrap();
    client_io.shutdown().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("malformed preface timed out")
        .unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn payload_larger_than_flow_control_window_round_trips() {
    let (client_io, server_io) = tokio::io::duplex(512 * 1024);
    let payload: Vec<u8> = (0..(H2_WINDOW as usize + 512 * 1024))
        .map(|value| (value % 251) as u8)
        .collect();
    let expected = payload.clone();
    let server = tokio::spawn(async move {
        let mut carrier = accept(server_io).await.unwrap();
        let mut received = vec![0u8; expected.len()];
        carrier.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
    });
    let mut client = connect(client_io, "example.com").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), client.write_all(&payload))
        .await
        .expect("flow-controlled upload stalled")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server did not consume the upload")
        .unwrap();
}

#[tokio::test]
async fn application_half_close_reaches_the_peer() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut carrier = accept(server_io).await.unwrap();
        let mut received = Vec::new();
        carrier.read_to_end(&mut received).await.unwrap();
        received
    });
    let mut client = connect(client_io, "example.com").await.unwrap();
    client.write_all(b"final payload").await.unwrap();
    client.shutdown().await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("peer did not observe HTTP/2 end-of-stream")
        .unwrap();
    assert_eq!(received, b"final payload");
}

#[tokio::test]
async fn later_streams_receive_normal_not_found() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move { accept(server_io).await.unwrap() });
    let (send_request, connection) = configure_client()
        .handshake::<_, Bytes>(client_io)
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_request = send_request.ready().await.unwrap();
    let (first_response, _first_body) = send_request
        .send_request(
            raw_request(
                Method::POST,
                CARRIER_PATH,
                Some(GRPC_MEDIA_TYPE),
                Some("trailers"),
            ),
            false,
        )
        .unwrap();
    assert_eq!(first_response.await.unwrap().status(), StatusCode::OK);
    let _carrier = server.await.unwrap();

    send_request = send_request.ready().await.unwrap();
    let (second_response, _second_body) = send_request
        .send_request(
            raw_request(
                Method::POST,
                "/v1/other",
                Some(GRPC_MEDIA_TYPE),
                Some("trailers"),
            ),
            true,
        )
        .unwrap();
    assert_eq!(
        second_response.await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    driver.abort();
}

#[tokio::test]
async fn connect_rejects_non_ok_response() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = configure_server()
            .handshake::<_, Bytes>(server_io)
            .await
            .unwrap();
        let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
        let response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(())
            .unwrap();
        respond.send_response(response, true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), connection.accept()).await;
    });
    let error = tokio::time::timeout(Duration::from_secs(2), connect(client_io, "example.com"))
        .await
        .expect("client did not process non-OK response")
        .expect_err("non-OK carrier response was accepted");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("503"));
    server.await.unwrap();
}
