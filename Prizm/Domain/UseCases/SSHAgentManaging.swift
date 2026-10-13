import Foundation

nonisolated struct SSHApproval: Identifiable, Equatable {
    let id: UUID
    let keyName: String
    let fingerprint: String
    var hostFingerprint: String? = nil
    var forwardingHostFingerprints: [String] = []
    let username: String
}

@MainActor
protocol SSHAgentManaging: AnyObject {
    var enabled: Bool { get }
    var socketPath: String { get }
    var status: String { get }
    var errorMessage: String? { get }
    var approval: SSHApproval? { get }
    var onChange: (@MainActor () -> Void)? { get set }
    func setEnabled(_ enabled: Bool)
    func setVaultUnlocked(_ unlocked: Bool)
    func shutdown()
    func respond(to id: UUID, allow: Bool, rememberUntilLock: Bool)
}

extension SSHAgentManaging {
    func respond(to id: UUID, allow: Bool) { respond(to: id, allow: allow, rememberUntilLock: false) }
}
