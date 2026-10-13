import AppKit
import SwiftUI

/// SwiftUI openWindow creates the window asynchronously. Activation must happen
/// after its native window is attached, rather than while the scene is opening.
@MainActor
final class SSHApprovalWindowActivator {
    private let activateApplication: () -> Void
    private weak var raisedWindow: NSWindow?
    private var originalState: (level: NSWindow.Level, behavior: NSWindow.CollectionBehavior, hides: Bool)?
    init(activateApplication: @escaping () -> Void = { NSApplication.shared.activate() }) {
        self.activateApplication = activateApplication
    }
    func bringToFront(_ window: NSWindow) {
        if raisedWindow !== window {
            restoreWindowPriority()
            raisedWindow = window
            originalState = (window.level, window.collectionBehavior, window.hidesOnDeactivate)
        }
        // A background app's activation request can be declined by macOS. Give
        // only the pending approval higher priority than ordinary Terminal windows.
        // Restore these properties when the request ends or its view detaches.
        window.level = .floating
        window.hidesOnDeactivate = false
        window.collectionBehavior.remove(.canJoinAllSpaces)
        window.collectionBehavior.insert(.moveToActiveSpace)
        window.deminiaturize(nil)
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        activateApplication()
    }

    func restoreWindowPriority() {
        if let window = raisedWindow, let state = originalState {
            window.level = state.level
            window.collectionBehavior = state.behavior
            window.hidesOnDeactivate = state.hides
        }
        raisedWindow = nil
        originalState = nil
    }
}

/// AppKit is required to order the actual approval window; SwiftUI's openWindow
/// does not guarantee application activation or expose its NSWindow.
struct SSHApprovalWindowAnchor: NSViewRepresentable {
    let requestID: UUID?
    func makeNSView(context: Context) -> SSHApprovalWindowAnchorView {
        SSHApprovalWindowAnchorView()
    }
    func updateNSView(_ view: SSHApprovalWindowAnchorView, context: Context) {
        view.requestID = requestID
        view.showApprovalIfNeeded()
    }
}

@MainActor
final class SSHApprovalWindowAnchorView: NSView {
    var requestID: UUID?
    private var presentedRequestID: UUID?
    private let activator: SSHApprovalWindowActivator

    init(activator: SSHApprovalWindowActivator = SSHApprovalWindowActivator()) {
        self.activator = activator
        super.init(frame: .zero)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        showApprovalIfNeeded()
    }

    func showApprovalIfNeeded() {
        guard let window, let id = requestID else {
            activator.restoreWindowPriority()
            presentedRequestID = nil
            return
        }
        guard id != presentedRequestID else { return }
        // Order after the SwiftUI render transaction finishes. If the request was
        // cancelled or the view detached in the meantime, do not steal focus.
        DispatchQueue.main.async { [weak self, weak window] in
            guard let self, let window, self.window === window,
                  self.requestID == id, self.presentedRequestID != id else { return }
            self.presentedRequestID = id
            self.activator.bringToFront(window)
        }
    }
}
