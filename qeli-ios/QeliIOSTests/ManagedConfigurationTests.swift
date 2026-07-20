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
}
