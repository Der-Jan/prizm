import Combine
import SwiftUI

@MainActor
final class SSHAgentViewModel: ObservableObject {
    private let manager: any SSHAgentManaging
    @Published private(set) var enabled = false
    @Published private(set) var status = ""
    @Published private(set) var errorMessage: String?
    @Published private(set) var approval: SSHApproval?
    var presentApproval: (() -> Void)?
    let socketPath: String

    init(manager: any SSHAgentManaging) {
        self.manager = manager
        socketPath = manager.socketPath
        manager.onChange = { [weak self] in self?.refresh() }
        refresh()
    }

    func setEnabled(_ value: Bool) { manager.setEnabled(value) }
    func respond(_ request: SSHApproval, allow: Bool, rememberUntilLock: Bool = false) { manager.respond(to: request.id, allow: allow, rememberUntilLock: rememberUntilLock) }

    private func refresh() {
        enabled = manager.enabled
        status = manager.status
        let previousApproval = approval
        approval = manager.approval
        if approval != nil, approval != previousApproval { presentApproval?() }
        let error = manager.errorMessage
        if let error, error != errorMessage {
            AccessibilityNotification.Announcement(error).post()
        }
        errorMessage = error
    }
}
