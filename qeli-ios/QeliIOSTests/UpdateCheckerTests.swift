import XCTest
@testable import Qeli

final class UpdateCheckerTests: XCTestCase {
    func testVersionNormalizationAndNumericComparison() throws {
        XCTAssertEqual(try UpdateChecker.normalize(" v0.7.12-beta+5 "), "0.7.12")
        XCTAssertTrue(try UpdateChecker.isNewer("0.10.0", than: "0.9.9"))
        XCTAssertFalse(try UpdateChecker.isNewer("v0.7.12", than: "0.7.12+715"))
        XCTAssertFalse(try UpdateChecker.isNewer("0.7.11", than: "0.7.12"))
    }

    func testPrivatePathRejectsEitherFamilyLeakAndExcludedRoutes() throws {
        let base = """
        [qeli]
        server = vpn.example.com:443
        user = alice
        pass = secret
        """
        XCTAssertTrue((try VPNConfig(parsing: base)).hasPrivateUpdatePath())

        for narrowing in [
            "gateway = false",
            "allow_ipv4_leak = true",
            "allow_ipv6_leak = true",
            "allow_lan = true",
            "exclude = 203.0.113.0/24",
        ] {
            let config = try VPNConfig(parsing: base + "\n" + narrowing)
            XCTAssertFalse(config.hasPrivateUpdatePath(), narrowing)
        }
        XCTAssertFalse(
            (try VPNConfig(parsing: base)).hasPrivateUpdatePath(globalAllowLAN: true)
        )
    }

    private final class ByteCounter { var reads = 0 }
    private struct Bytes: AsyncSequence {
        typealias Element = UInt8
        let total: Int
        let counter: ByteCounter
        struct AsyncIterator: AsyncIteratorProtocol {
            var remaining: Int
            let counter: ByteCounter
            mutating func next() async -> UInt8? {
                guard remaining > 0 else { return nil }
                remaining -= 1
                counter.reads += 1
                return 65
            }
        }
        func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(remaining: total, counter: counter)
        }
    }

    func testBoundedReleaseStreamAcceptsExactLimit() async throws {
        let counter = ByteCounter()
        let result = try await UpdateChecker.boundedResponse(Bytes(total: 4, counter: counter), maximumBytes: 4)
        XCTAssertEqual(result, Data("AAAA".utf8))
        XCTAssertEqual(counter.reads, 4)
    }

    func testOversizedReleaseStreamStopsBeforeReadingItsRemainingBody() async {
        let counter = ByteCounter()
        do {
            _ = try await UpdateChecker.boundedResponse(Bytes(total: 1_000_000, counter: counter), maximumBytes: 4)
            XCTFail("Expected size rejection")
        } catch UpdateCheckerError.responseTooLarge {}
        catch { XCTFail("Unexpected error: \(error)") }
        XCTAssertEqual(counter.reads, 5)
    }

    func testCancelledReleaseReadDoesNotConsumeStream() async throws {
        let counter = ByteCounter()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await UpdateChecker.boundedResponse(Bytes(total: 10, counter: counter), maximumBytes: 4)
        }
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch is CancellationError {}
        XCTAssertEqual(counter.reads, 0)
    }

}
