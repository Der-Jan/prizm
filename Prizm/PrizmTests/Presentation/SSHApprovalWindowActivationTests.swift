import AppKit
import XCTest
@testable import Prizm

@MainActor
final class SSHApprovalWindowActivationTests: XCTestCase {
    func testRestoresAndRaisesApprovalBeforeActivatingApplication() {
        let window = RecordingApprovalWindow()
        let activator = SSHApprovalWindowActivator { window.calls.append("activate") }
        activator.bringToFront(window)
        XCTAssertEqual(window.calls, ["restore", "key", "front", "activate"])
    }
    func testCancelledOrDetachedApprovalDoesNotActivate() async {
        for detach in [false, true] {
            let window = RecordingApprovalWindow()
            let activator = SSHApprovalWindowActivator { window.calls.append("activate") }
            let anchor = SSHApprovalWindowAnchorView(activator: activator)
            window.contentView = anchor
            anchor.requestID = UUID()
            anchor.showApprovalIfNeeded()
            if detach { window.contentView = nil } else { anchor.requestID = nil }
            await nextRunLoop()
            XCTAssertTrue(window.calls.isEmpty)
        }
    }

    func testAttachedApprovalActivatesOnlyOncePerRequest() async {
        let window = RecordingApprovalWindow()
        let activator = SSHApprovalWindowActivator { window.calls.append("activate") }
        let anchor = SSHApprovalWindowAnchorView(activator: activator)
        window.contentView = anchor
        anchor.requestID = UUID()
        anchor.showApprovalIfNeeded()
        anchor.showApprovalIfNeeded()
        await nextRunLoop()
        XCTAssertEqual(window.calls, ["restore", "key", "front", "activate"])
        anchor.requestID = UUID()
        anchor.showApprovalIfNeeded()
        await nextRunLoop()
        XCTAssertEqual(window.calls.count, 8)
    }

    func testPendingApprovalIsAboveNormalApplicationWindows() async {
        let window = RecordingApprovalWindow()
        let originalLevel = window.level
        let originalBehavior = window.collectionBehavior
        window.hidesOnDeactivate = true
        let anchor = SSHApprovalWindowAnchorView(activator: SSHApprovalWindowActivator {})
        window.contentView = anchor
        anchor.requestID = UUID()
        anchor.showApprovalIfNeeded()
        await nextRunLoop()
        XCTAssertGreaterThan(window.level.rawValue, NSWindow.Level.normal.rawValue)
        XCTAssertFalse(window.hidesOnDeactivate)
        XCTAssertTrue(window.collectionBehavior.contains(.moveToActiveSpace))
        anchor.requestID = nil
        anchor.showApprovalIfNeeded()
        await nextRunLoop()
        XCTAssertEqual(window.level, originalLevel)
        XCTAssertEqual(window.collectionBehavior, originalBehavior)
        XCTAssertTrue(window.hidesOnDeactivate)
    }

    func testClosingApprovalRestoresWindowPriority() async {
        let window = RecordingApprovalWindow()
        let originalLevel = window.level
        let originalBehavior = window.collectionBehavior
        window.hidesOnDeactivate = true
        let anchor = SSHApprovalWindowAnchorView(activator: SSHApprovalWindowActivator {})
        window.contentView = anchor
        anchor.requestID = UUID()
        anchor.showApprovalIfNeeded()
        await nextRunLoop()
        window.contentView = nil
        await nextRunLoop()
        XCTAssertEqual(window.level, originalLevel)
        XCTAssertEqual(window.collectionBehavior, originalBehavior)
        XCTAssertTrue(window.hidesOnDeactivate)
    }

    private func nextRunLoop() async {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
    }

}

@MainActor
private final class RecordingApprovalWindow: NSWindow {
    var calls: [String] = []
    init() {
        super.init(contentRect: .zero, styleMask: [.titled], backing: .buffered, defer: true)
    }
    override func deminiaturize(_ sender: Any?) { calls.append("restore") }
    override func makeKeyAndOrderFront(_ sender: Any?) { calls.append("key") }
    override func orderFrontRegardless() { calls.append("front") }
}
