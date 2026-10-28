import Foundation
import XCTest
@testable import Qeli

final class DisconnectLogSettingsTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!
    private var settings: SettingsStore!
    private var journal: SharedTunnelStore!

    override func setUp() {
        super.setUp()
        suite = "qeli.disconnect.log.tests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
        settings = SettingsStore(suiteName: suite)
        journal = SharedTunnelStore(suiteName: suite)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
        settings = nil
        journal = nil
        defaults = nil
        super.tearDown()
    }

    func testFreshAndLegacySettingsDefaultToClearingWithoutLosingPreferences() throws {
        XCTAssertTrue(settings.load().clearLogOnDisconnect)
        let legacy = Data(#"{"allowLAN":true,"logLevel":"debug","language":"ru"}"#.utf8)
        defaults.set(legacy, forKey: "app.settings.v1")
        let value = settings.load()
        XCTAssertTrue(value.clearLogOnDisconnect)
        XCTAssertTrue(value.allowLAN)
        XCTAssertEqual(value.logLevel, .debug)
        XCTAssertEqual(value.language, .ru)
    }

    func testDisabledPreferenceSurvivesReloadAndDoesNotImmediatelyEraseHistory() {
        journal.appendLog("connected")
        var value = settings.load()
        value.clearLogOnDisconnect = false
        settings.save(value)
        XCTAssertFalse(SettingsStore(suiteName: suite).load().clearLogOnDisconnect)
        XCTAssertEqual(journal.logLines().map(\.message), ["connected"])
        value.clearLogOnDisconnect = true
        settings.save(value)
        XCTAssertTrue(SettingsStore(suiteName: suite).load().clearLogOnDisconnect)
        XCTAssertEqual(journal.logLines().map(\.message), ["connected"])
    }

    func testDefaultStopRemovesPersistedHistoryAndRejectsLateCallbacks() {
        journal.appendLog("connected")
        journal.appendLog("user disconnect")
        journal.finishLogSession(clear: settings.load().clearLogOnDisconnect)
        journal.appendLog("late stop callback")
        XCTAssertNil(defaults.data(forKey: "tunnel.log.v1"))
        XCTAssertTrue(SharedTunnelStore(suiteName: suite).logLines().isEmpty)
    }

    func testDisabledStopRetainsHistoryAfterReopeningButSealsOldWriter() {
        var value = settings.load()
        value.clearLogOnDisconnect = false
        settings.save(value)
        journal.appendLog("ERROR: connection ended")
        journal.finishLogSession(clear: SettingsStore(suiteName: suite).load().clearLogOnDisconnect)
        journal.appendLog("late callback")
        XCTAssertEqual(SharedTunnelStore(suiteName: suite).logLines().map(\.message),
                       ["ERROR: connection ended"])
    }

    func testLatestPreferenceIsReadAtStopRatherThanAtSessionStart() {
        journal.appendLog("connected with default settings")
        var value = settings.load()
        value.clearLogOnDisconnect = false
        settings.save(value)
        journal.finishLogSession(clear: SettingsStore(suiteName: suite).load().clearLogOnDisconnect)
        XCTAssertEqual(journal.logLines().map(\.message), ["connected with default settings"])
    }

    func testStartupAndTransportErrorsSurviveDefaultCleanupAndReopening() {
        for failure in ["SERVER KEY MISMATCH", "Authentication failed", "Connection refused"] {
            let writer = SharedTunnelStore(suiteName: suite)
            writer.clearLog()
            writer.appendLog("Connecting")
            writer.appendLog("ERROR: \(failure)")
            writer.finishLogSession(clear: settings.load().clearLogOnDisconnect, terminalError: true)
            writer.appendLog("stale teardown callback")
            writer.finishLogSession(clear: true) // a later system stop must not erase the error
            XCTAssertEqual(SharedTunnelStore(suiteName: suite).logLines().map(\.message),
                           ["Connecting", "ERROR: \(failure)"])
        }
    }

    @MainActor
    func testPreProviderConfigurationFailureIsWrittenToJournal() async {
        let manager = TunnelManager(sharedStore: journal)
        let invalid = Profile(name: "invalid", configText: "[qeli]\nunknown_log_fixture_option = true\n")
        do {
            try await manager.connect(profile: invalid, settings: AppSettings())
            XCTFail("invalid connection configuration was accepted")
        } catch {
            XCTAssertTrue(journal.logLines().contains { $0.message.hasPrefix("ERROR starting VPN:") })
        }
    }

    func testErrorHistoryCanStillBeClearedManually() {
        journal.appendLog("ERROR: SERVER KEY MISMATCH")
        journal.finishLogSession(clear: true, terminalError: true)
        SharedTunnelStore(suiteName: suite).clearLog()
        XCTAssertTrue(journal.logLines().isEmpty)
    }

    func testOldSessionCannotWriteOrClearNewSession() {
        journal.appendLog("old session")
        journal.finishLogSession(clear: false)
        let next = SharedTunnelStore(suiteName: suite)
        next.appendLog("new session")
        journal.appendLog("stale native callback")
        journal.finishLogSession(clear: true)
        XCTAssertEqual(next.logLines().map(\.message), ["old session", "new session"])
    }

    func testManualClearDoesNotPreventFurtherActiveSessionLogging() {
        journal.appendLog("before manual clear")
        journal.clearLog()
        journal.appendLog("reconnecting")
        journal.appendLog("connected again")
        XCTAssertEqual(journal.logLines().map(\.message), ["reconnecting", "connected again"])
    }

    func testConcurrentCallbacksCannotRecreateClearedHistory() {
        let writer = journal!
        DispatchQueue.concurrentPerform(iterations: 64) { index in
            writer.appendLog("event \(index)")
            if index == 32 { writer.finishLogSession(clear: true) }
        }
        writer.appendLog("after stop")
        XCTAssertTrue(SharedTunnelStore(suiteName: suite).logLines().isEmpty)
    }
}
