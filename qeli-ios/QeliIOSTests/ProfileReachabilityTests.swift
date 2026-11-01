import XCTest
@testable import Qeli

final class ProfileReachabilityTests: XCTestCase {
    func testConnectedProviderIsNotAnEndpointFailureOrAnInventedRTT() {
        let state = ReachabilityState.activeTunnel(.connected)
        XCTAssertEqual(state, .connectedWithoutRTT)
        if case .reachable = state { XCTFail("No in-tunnel RTT was measured") }
        if case .unavailable = state { XCTFail("An absent VPN listener on the gateway is not VPN failure") }
    }

    func testTransitionalAndStoppedStatesDoNotClaimConnectedOrLatency() {
        for phase in [TunnelPhase.disconnected, .preparing, .connecting, .reconnecting,
                      .waiting, .disconnecting, .error] {
            XCTAssertEqual(ReachabilityState.activeTunnel(phase), .idle)
        }
    }
}
