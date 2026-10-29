import Foundation
import XCTest
@testable import Qeli

#if os(Linux)
import QeliNative

/// Exercises the real C ABI through the production Swift diagnostic reader. The Linux
/// core deliberately lacks iOS packet-I/O capabilities; raw lifecycle handles let us test
/// its read-only API without weakening the live adapter's capability gate. No runner starts.
final class NativeCarrierDiagnosticsABITests: XCTestCase {
    private var config: String {
        """
        [qeli]
        server = 192.0.2.1:443
        proto = tcp
        user = fixture
        pass = fixture-password
        key = \(String(repeating: "1", count: 64))
        mode = fake-tls
        gateway = false
        """
    }

    func testProductionReaderRequiresVersionAndCapability() throws {
        XCTAssertEqual(QeliNativeTransport.compatibilityABIVersion, 0x0001_0011)
        XCTAssertGreaterThanOrEqual(QeliNativeTransport.loadedABIVersion(), 0x0001_0011)
        XCTAssertNotEqual(qeli_client_core_capabilities() & QeliNativeTransport.coreCarrierDiagnostics, 0)
        #if os(Linux)
        XCTAssertThrowsError(try QeliNativeTransport.requireCompatible())
        #else
        XCTAssertNoThrow(try QeliNativeTransport.requireCompatible())
        #endif
    }

    func testCreatedHandleReportsUnavailableRuntimeWithoutInventingCarriers() throws {
        try withHandle { handle in
            let snapshot = try XCTUnwrap(QeliNativeTransport.readCarrierDiagnostics(handle: handle))
            XCTAssertTrue(snapshot.supported)
            XCTAssertFalse(snapshot.runtimeAvailable)
            XCTAssertFalse(snapshot.finished)
            XCTAssertTrue(snapshot.carriers.isEmpty)
            let encoded = try JSONEncoder().encode(snapshot)
            let text = String(decoding: encoded, as: UTF8.self)
            XCTAssertFalse(text.contains("192.0.2.1"))
            XCTAssertFalse(text.contains("fixture-password"))
            XCTAssertEqual(CarrierDiagnosticsSnapshot.parse(encoded), snapshot)
        }
    }

    func testDiagnosticsReadsDoNotConsumeLifecycleEvents() throws {
        try withHandle { control in
            try withHandle { sampled in
                XCTAssertEqual(qeli_client_start(control), 0)
                XCTAssertEqual(qeli_client_start(sampled), 0)
                defer { _ = qeli_client_stop(control); _ = qeli_client_stop(sampled) }
                for _ in 0..<5 { XCTAssertNotNil(QeliNativeTransport.readCarrierDiagnostics(handle: sampled)) }
                let baseline = try drain(control)
                let actual = try drain(sampled)
                XCTAssertFalse(baseline.isEmpty)
                XCTAssertEqual(actual.map(\.kind), baseline.map(\.kind))
                XCTAssertEqual(actual.map(\.state), baseline.map(\.state))
                XCTAssertEqual(actual.map(\.sequence), baseline.map(\.sequence))
                XCTAssertEqual(actual.map(\.payload), baseline.map(\.payload))
            }
        }
    }

    func testRepeatedReadersAndStatsRemainAvailableAfterLocalStop() throws {
        try withHandle { handle in
            XCTAssertNotNil(QeliNativeTransport.readCarrierDiagnostics(handle: handle))
            XCTAssertEqual(qeli_client_stop(handle), 0)
            XCTAssertNotNil(QeliNativeTransport.readCarrierDiagnostics(handle: handle))
            var stats = qeli_client_stats_t()
            stats.struct_size = UInt32(MemoryLayout<qeli_client_stats_t>.size)
            stats.abi_version = QeliNativeTransport.compatibilityABIVersion
            XCTAssertEqual(qeli_client_stats(handle, &stats), 0)
        }
    }

    private func withHandle<T>(_ operation: (UInt64) throws -> T) throws -> T {
        let bytes = Data(config.utf8)
        var handle: UInt64 = 0
        let status = bytes.withUnsafeBytes { raw in
            qeli_client_new(raw.bindMemory(to: UInt8.self).baseAddress, bytes.count,
                            QeliNativeTransport.basePlatformCapabilities, 128, &handle)
        }
        guard status == 0, handle != 0 else {
            throw QeliNativeError.operationFailed("fixture handle create (\(status))")
        }
        defer { XCTAssertEqual(qeli_client_free(handle), 0) }
        return try operation(handle)
    }

    private func drain(_ handle: UInt64) throws -> [QeliTransportEvent] {
        var events: [QeliTransportEvent] = []
        for _ in 0..<32 {
            var event = qeli_client_event_t()
            event.struct_size = UInt32(MemoryLayout<qeli_client_event_t>.size)
            event.abi_version = QeliNativeTransport.compatibilityABIVersion
            var buffer = [UInt8](repeating: 0, count: 4096)
            var length = 0
            let status = buffer.withUnsafeMutableBufferPointer {
                qeli_client_poll_event(handle, &event, $0.baseAddress, $0.count, &length)
            }
            if status == 1 { return events }
            guard status == 0, length <= buffer.count else {
                throw QeliNativeError.operationFailed("fixture event read (\(status))")
            }
            events.append(QeliTransportEvent(
                kind: event.kind, state: event.state, payloadFormat: event.payload_format,
                sequence: event.sequence, planGeneration: event.plan_generation, errorCode: event.error_code,
                payload: String(decoding: buffer.prefix(length), as: UTF8.self)
            ))
        }
        XCTFail("Unexpectedly unbounded lifecycle events")
        return events
    }
}

#else
/// On Apple platforms use the app-owned wrapper rather than linking a second static
/// Rust library into the XCTest bundle (which would create a separate handle registry).
final class NativeCarrierDiagnosticsAppleTests: XCTestCase {
    private func makeTransport() throws -> QeliNativeTransport {
        try QeliNativeTransport(config: """
        [qeli]
        server = 192.0.2.1:443
        proto = tcp
        user = fixture
        pass = fixture-password
        key = \(String(repeating: "1", count: 64))
        mode = fake-tls
        gateway = false
        """)
    }

    func testAppOwnedReaderHasRequiredABIAndUnavailableRuntime() throws {
        try QeliNativeTransport.requireCompatible()
        let transport = try makeTransport()
        let snapshot = try XCTUnwrap(transport.carrierDiagnostics())
        XCTAssertFalse(snapshot.runtimeAvailable)
        XCTAssertTrue(snapshot.carriers.isEmpty)
        transport.stop()
        XCTAssertNotNil(transport.carrierDiagnostics())
    }

    func testAppOwnedReaderDoesNotConsumeLifecycleEvents() throws {
        let transport = try makeTransport()
        try transport.start()
        defer { transport.stop() }
        for _ in 0..<5 { XCTAssertNotNil(transport.carrierDiagnostics()) }
        XCTAssertNotNil(try transport.pollEvent())
    }
}

#endif
