import XCTest
@testable import Qeli

final class ProfileAutoProbePolicyTests: XCTestCase {
    func testPollingIsOptInAndLegacySettingsKeepTheirValues() throws {
        let legacy = Data(#"{"allowLAN":true,"logTimeFormat":"epoch"}"#.utf8)
        let settings = try JSONDecoder().decode(AppSettings.self, from: legacy)
        XCTAssertFalse(settings.autoProbeProfiles)
        XCTAssertFalse(settings.retainLastErrorReport)
        XCTAssertEqual(settings.probeIntervalSeconds, 30)
        XCTAssertTrue(settings.allowLAN)
        XCTAssertEqual(settings.logTimeFormat, .epoch)
    }

    func testIntervalLimitsAreAppliedWhenReadingSavedSettings() throws {
        for (raw, expected) in [(-1, 10), (0, 10), (10, 10), (45, 45), (3600, 3600), (Int.max, 3600)] {
            let data = Data("{\"autoProbeProfiles\":true,\"probeIntervalSeconds\":\(raw)}".utf8)
            let settings = try JSONDecoder().decode(AppSettings.self, from: data)
            XCTAssertTrue(settings.autoProbeProfiles)
            XCTAssertEqual(settings.probeIntervalSeconds, expected)
        }
    }

    func testSettingsRoundTripKeepsPollingAndRetentionPreferences() throws {
        var original = AppSettings()
        original.autoProbeProfiles = true
        original.probeIntervalSeconds = 75
        original.retainLastErrorReport = true
        let loaded = try JSONDecoder().decode(AppSettings.self, from: JSONEncoder().encode(original))
        XCTAssertEqual(loaded, original)
    }

    func testOnlyForegroundDisconnectedOptInCanStartAutomaticNetworkWork() {
        for enabled in [false, true] {
            for foreground in [false, true] {
                for busy in [false, true] {
                    XCTAssertEqual(ProfileAutoProbePolicy.canStartSweep(
                        enabled: enabled, foreground: foreground, tunnelBusy: busy,
                        systemDisconnected: true, now: 123, lastSweep: nil
                    ), enabled && foreground && !busy)
                }
            }
        }
    }

    func testVisibleErrorCannotProbeWhileSystemStillHoldsTheTunnel() {
        XCTAssertFalse(ProfileAutoProbePolicy.canStartSweep(
            enabled: true, foreground: true, tunnelBusy: false,
            systemDisconnected: false, now: 100, lastSweep: nil
        ))
        XCTAssertTrue(ProfileAutoProbePolicy.canStartSweep(
            enabled: true, foreground: true, tunnelBusy: false,
            systemDisconnected: true, now: 100, lastSweep: nil
        ))
    }

    func testRapidForegroundAndSettingChangesCannotTriggerRepeatedSweeps() {
        for now in [100.0, 100.1, 109.999] {
            XCTAssertFalse(ProfileAutoProbePolicy.canStartSweep(
                enabled: true, foreground: true, tunnelBusy: false,
                systemDisconnected: true, now: now, lastSweep: 100
            ))
        }
        XCTAssertTrue(ProfileAutoProbePolicy.canStartSweep(
            enabled: true, foreground: true, tunnelBusy: false,
            systemDisconnected: true, now: 110, lastSweep: 100
        ))
        XCTAssertTrue(ProfileAutoProbePolicy.canStartSweep(
            enabled: true, foreground: true, tunnelBusy: false,
            systemDisconnected: true, now: 1, lastSweep: 100
        ))
    }
}
