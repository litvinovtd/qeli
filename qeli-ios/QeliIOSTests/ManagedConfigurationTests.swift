import XCTest
@testable import Qeli

final class ManagedConfigurationTests: XCTestCase {
    func testParsesTypedManagedValues() {
        let id = UUID()
        let value = ManagedConfigurationReader.parse([
            "configurationVersion": 1,
            "activeProfileID": id.uuidString,
            "onDemandEnabled": true,
            "widgetControlsEnabled": false
        ])

        XCTAssertTrue(value.isManaged)
        XCTAssertEqual(value.configurationVersion, 1)
        XCTAssertEqual(value.activeProfileID, id)
        XCTAssertTrue(value.hasActiveProfilePolicy)
        XCTAssertEqual(value.onDemandEnabled, true)
        XCTAssertEqual(value.widgetControlsEnabled, false)
    }

    func testRejectsMalformedValuesWithoutInventingDefaults() {
        let value = ManagedConfigurationReader.parse([
            "activeProfileID": "not-a-uuid",
            "onDemandEnabled": "yes"
        ])

        XCTAssertTrue(value.isManaged)
        XCTAssertNil(value.activeProfileID)
        XCTAssertTrue(value.hasActiveProfilePolicy)
        XCTAssertNil(value.onDemandEnabled)
        XCTAssertNil(value.widgetControlsEnabled)
    }

    func testMissingDictionaryIsUnmanaged() {
        XCTAssertEqual(
            ManagedConfigurationReader.parse(nil),
            QeliManagedConfiguration()
        )
    }

    func testOmittedActiveProfileDoesNotCreatePolicy() {
        let value = ManagedConfigurationReader.parse(["onDemandEnabled": true])

        XCTAssertFalse(value.hasActiveProfilePolicy)
        XCTAssertNil(value.activeProfileID)
    }

    func testRejectsFractionalAndInvalidNumericPolicies() {
        let invalid: [Any] = [
            NSNumber(value: 0.5), NSNumber(value: 1.5), NSNumber(value: -0.5),
            NSNumber(value: 2), NSNumber(value: -1), NSNumber(value: Double.nan),
            NSNumber(value: Double.infinity), NSNumber(value: -Double.infinity),
            "1", NSNull()
        ]
        for raw in invalid {
            let value = ManagedConfigurationReader.parse([
                "onDemandEnabled": raw, "widgetControlsEnabled": raw
            ])
            XCTAssertNil(value.onDemandEnabled, "Unexpected policy for \(raw)")
            XCTAssertNil(value.widgetControlsEnabled, "Unexpected policy for \(raw)")
        }
    }

    func testRetainsExactNumericBooleanCompatibility() {
        for raw in [NSNumber(value: 0), NSNumber(value: 0.0)] {
            XCTAssertEqual(ManagedConfigurationReader.parse(["onDemandEnabled": raw]).onDemandEnabled, false)
        }
        for raw in [NSNumber(value: 1), NSNumber(value: 1.0)] {
            XCTAssertEqual(ManagedConfigurationReader.parse(["onDemandEnabled": raw]).onDemandEnabled, true)
        }
    }

    func testVersionRequiresAnExactRepresentableInteger() {
        let invalid: [Any] = [
            true, false, NSNumber(value: 1.5), NSNumber(value: Double.nan),
            NSNumber(value: Double.infinity), NSNumber(value: -Double.infinity),
            NSNumber(value: UInt64.max), "1", NSNull()
        ]
        for raw in invalid {
            XCTAssertNil(ManagedConfigurationReader.parse(["configurationVersion": raw]).configurationVersion)
        }
        for integer in [Int.min, -1, 0, 1, Int.max] {
            XCTAssertEqual(
                ManagedConfigurationReader.parse(["configurationVersion": NSNumber(value: integer)]).configurationVersion,
                integer
            )
        }
        XCTAssertEqual(
            ManagedConfigurationReader.parse(["configurationVersion": NSNumber(value: 1.0)]).configurationVersion, 1
        )
    }

}
