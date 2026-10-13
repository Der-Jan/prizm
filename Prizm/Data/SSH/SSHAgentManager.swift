import Foundation
import os.log

@MainActor
final class SSHAgentManager: SSHAgentManaging {
    private let logger = Logger(subsystem: "com.prizm", category: "SSHAgent")
    private let vault: any VaultRepository
    private let crypto: any PrizmCryptoService
    private let defaults: UserDefaults
    private let approvalTimeout: Duration
    private var transport: SSHAgentSocket?
    private var unlocked = false
    private var generation = UUID()
    private struct Decision { let allow: Bool; let remember: Bool }
    private var pending: CheckedContinuation<Decision, Never>?
    private struct ConnectionState: Equatable {
        var bindings: [SSHSessionBinding] = []
        var failed = false
    }
    private struct Grant: Hashable {
        let key: Data
        let username: String
        let hosts: [Data]
    }
    private var connections: [UUID: ConnectionState] = [:]
    private var grants: Set<Grant> = []
    private var approvalConnection: UUID?
    private var timeout: Task<Void, Never>?
    private(set) var enabled = false
    let socketPath: String
    private(set) var errorMessage: String?
    private(set) var approval: SSHApproval?
    var onChange: (@MainActor () -> Void)?
    var status: String {
        if !enabled { return "Disabled" }
        return unlocked ? "Running" : "Running — unlock the vault to use keys"
    }

    init(vault: any VaultRepository, crypto: any PrizmCryptoService,
         defaults: UserDefaults = .standard, approvalTimeout: Duration = .seconds(45), socketPath: String = NSHomeDirectory() + "/.bitwarden-ssh-agent.sock") {
        self.vault = vault
        self.crypto = crypto
        self.defaults = defaults
        self.approvalTimeout = approvalTimeout
        self.socketPath = socketPath
        if defaults.bool(forKey: "sshAgent.enabled") { setEnabled(true) }
    }

    func setEnabled(_ value: Bool) {
        guard value != enabled else { return }
        invalidateRequests()
        errorMessage = nil
        if value {
            do {
                let socket = SSHAgentSocket(path: socketPath, onDisconnect: { [weak self] id in
                    await self?.connectionClosed(id)
                }) { [weak self] packet, id in
                    guard let self else { return Data([5]) }
                    return await self.handle(packet, connectionID: id)
                }
                try socket.start()
                transport = socket
                enabled = true
                logger.info("SSH agent enabled")
            } catch {
                errorMessage = error.localizedDescription
                logger.error("SSH agent could not start")
            }
        } else {
            transport?.stop()
            transport = nil
            enabled = false
            logger.info("SSH agent disabled")
        }
        defaults.set(enabled, forKey: "sshAgent.enabled")
        onChange?()
    }

    func setVaultUnlocked(_ value: Bool) {
        // Root invokes this synchronously before any asynchronous key clearing.
        invalidateRequests()
        unlocked = value
        onChange?()
    }

    func shutdown() {
        invalidateRequests()
        unlocked = false
        transport?.stop()
        transport = nil
        enabled = false
        onChange?()
    }

    func respond(to id: UUID, allow: Bool, rememberUntilLock: Bool = false) {
        guard approval?.id == id else { return }
        let continuation = pending
        pending = nil
        approval = nil
        approvalConnection = nil
        timeout?.cancel()
        timeout = nil
        onChange?()
        continuation?.resume(returning: Decision(allow: allow, remember: allow && rememberUntilLock))
    }

    private func invalidateRequests() {
        generation = UUID()
        connections.removeAll()
        grants.removeAll()
        if let id = approval?.id { respond(to: id, allow: false) }
    }

    func connectionClosed(_ id: UUID) {
        connections.removeValue(forKey: id)
        if approvalConnection == id, let request = approval?.id { respond(to: request, allow: false) }
    }

    private func bind(_ reader: inout SSHReader, connectionID: UUID?) -> Data {
        guard let id = connectionID, enabled, unlocked, !Task.isCancelled else { return Data([28]) }
        guard connections[id] != nil || connections.count < 4 else { return Data([28]) }
        var state = connections[id] ?? ConnectionState()
        do {
            // Unknown extensions are unsupported, not evidence of a bad bind.
            guard try reader.text() == "session-bind@openssh.com" else { return Data([5]) }
            guard !state.failed, state.bindings.count < 16, state.bindings.last?.forwarded != false
            else { throw SSHAgentError.invalidPacket }
            let binding = try crypto.sshSessionBinding(reader: &reader)
            if let previous = state.bindings.first(where: { $0.session == binding.session }) {
                guard previous == binding else { throw SSHAgentError.invalidPacket }
                return Data([6]) // Identical forwarding binds are idempotent.
            }
            state.bindings.append(binding)
            connections[id] = state
            return Data([6])
        } catch {
            state.failed = true
            connections[id] = state
            logger.error("SSH session binding rejected")
            errorMessage = "The SSH session binding is invalid or unsupported. Reconnect with a supported host key."
            onChange?()
            return Data([28])
        }
    }

    private struct Identity {
        let id: String
        let name: String
        let blob: Data
        let algorithm: String
    }

    private func identities() async throws -> [Identity] {
        let items = try await vault.allItems()
        var identities: [Identity] = []
        for item in items where !item.isDeleted && item.reprompt == 0 {
            do {
                if let identity = try identity(for: item) { identities.append(identity) }
            } catch {
                // A malformed or unsupported vault entry must not poison every
                // other identity. Surface the skipped-entry error without logging keys.
                logger.error("Skipped an invalid or unsupported SSH key entry")
                errorMessage = "Some SSH keys are invalid or unsupported. Supported formats: unencrypted OpenSSH Ed25519 and PEM RSA."
            }
            if identities.count == 64 { break }
        }
        return identities
    }

    private func identity(for item: VaultItem) throws -> Identity? {
        guard case .sshKey(let key) = item.content, let line = key.publicKey,
              let secret = key.privateKey, !secret.isEmpty else { return nil }
        // Bound input before splitting/decoding it and before putting metadata
        // in the approval UI. Limits are measured in bytes, not grapheme clusters.
        guard line.utf8.count <= 16_384, secret.utf8.count <= 128_000 else { throw SSHAgentError.invalidKey }
        let fields = line.split(whereSeparator: { $0.isWhitespace })
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else { throw SSHAgentError.invalidKey }
        var reader = SSHReader(blob)
        let kind = try reader.text()
        guard kind == String(fields[0]) else { throw SSHAgentError.invalidKey }
        if kind == "ssh-ed25519" {
            guard try reader.string().count == 32 else { throw SSHAgentError.invalidKey }
            guard secret.contains("BEGIN OPENSSH PRIVATE KEY") else { throw SSHAgentError.unsupportedKey }
        } else if kind == "ssh-rsa" {
            guard secret.contains("BEGIN RSA PRIVATE KEY") || secret.contains("BEGIN PRIVATE KEY") else {
                throw SSHAgentError.unsupportedKey
            }
            let e = try reader.string(), n = try reader.string()
            guard (1...5).contains(e.count), (256...1025).contains(n.count) else { throw SSHAgentError.invalidKey }
        } else { throw SSHAgentError.unsupportedKey }
        try reader.end()
        let name = String(decoding: item.name.utf8.prefix(256), as: UTF8.self)
        return Identity(id: item.id, name: name, blob: blob, algorithm: kind)
    }

    /// Testable protocol boundary: every await is followed by a session check.
    func handle(_ packet: Data, connectionID: UUID? = nil) async -> Data {
        let session = generation
        let connection = connectionID.flatMap { connections[$0] }
        func current() -> Bool {
            session == generation && unlocked && enabled && !Task.isCancelled
                && connection == connectionID.flatMap { connections[$0] }
        }
        do {
            guard enabled, unlocked, !Task.isCancelled else { throw SSHAgentError.locked }
            guard packet.count <= SSHWire.maximumPacket else { throw SSHAgentError.invalidPacket }
            var reader = SSHReader(packet)
            let type = try reader.byte()
            if type == 27 { return bind(&reader, connectionID: connectionID) }
            guard connection?.failed != true else { throw SSHAgentError.invalidPacket }
            if type == 11 {
                try reader.end()
                let keys = try await identities()
                guard current() else { throw SSHAgentError.locked }
                var reply = Data([12]) + SSHWire.uint32(UInt32(keys.count))
                for key in keys {
                    reply += SSHWire.string(key.blob) + SSHWire.text(String(key.name.prefix(128)))
                }
                onChange?()
                return reply.count <= SSHWire.maximumPacket ? reply : Data([5])
            }
            guard type == 13 else { throw SSHAgentError.invalidPacket }
            let blob = try reader.string(), data = try reader.string(), flags = try reader.uint32()
            try reader.end()
            let keys = try await identities()
            guard current() else { throw SSHAgentError.locked }
            guard let key = keys.first(where: { $0.blob == blob }) else { throw SSHAgentError.invalidKey }
            let algorithm: String
            if key.algorithm == "ssh-ed25519", flags == 0 { algorithm = "ssh-ed25519" }
            else if key.algorithm == "ssh-rsa", flags == 2 { algorithm = "rsa-sha2-256" }
            else if key.algorithm == "ssh-rsa", flags == 4 { algorithm = "rsa-sha2-512" }
            else { throw SSHAgentError.invalidPacket }
            let authentication = try SSHWire.authenticationDetails(data, key: blob, algorithm: algorithm)
            let user = authentication.username
            let bindings = connection?.bindings ?? []
            if let destination = bindings.last {
                guard !destination.forwarded, destination.session == authentication.session,
                      authentication.hostKey == nil || authentication.hostKey == destination.hostKey
                else { throw SSHAgentError.invalidPacket }
            }
            let grant = bindings.isEmpty ? nil : Grant(key: blob, username: user, hosts: bindings.map(\.hostKey))
            let accepted: Decision
            if let grant, grants.contains(grant) {
                accepted = Decision(allow: true, remember: false)
            } else {
                guard approval == nil else { throw SSHAgentError.busy }
                let request = SSHApproval(id: UUID(), keyName: key.name, fingerprint: crypto.sshFingerprint(blob),
                    hostFingerprint: bindings.last.map { crypto.sshFingerprint($0.hostKey) },
                    forwardingHostFingerprints: bindings.dropLast().map { crypto.sshFingerprint($0.hostKey) }, username: user)
                accepted = await withTaskCancellationHandler {
                    await withCheckedContinuation { continuation in
                        guard !Task.isCancelled else { continuation.resume(returning: Decision(allow: false, remember: false)); return }
                        pending = continuation
                        approval = request
                        approvalConnection = connectionID
                        let duration = approvalTimeout
                        timeout = Task { [weak self] in
                            do { try await Task.sleep(for: duration) }
                            catch { return }
                            self?.respond(to: request.id, allow: false)
                        }
                        onChange?()
                    }
                } onCancel: {
                    Task { @MainActor [weak self] in self?.respond(to: request.id, allow: false) }
                }
            }
            guard accepted.allow, current() else { return Data([5]) }
            // Re-read after approval: deleted, changed and reprompt-protected keys
            // cannot reuse metadata captured before the dialog was displayed.
            let item = try await vault.itemDetail(id: key.id)
            guard current(),
                  !item.isDeleted, item.reprompt == 0, case .sshKey(let content) = item.content,
                  let privateKey = content.privateKey else { throw SSHAgentError.locked }
            guard try crypto.sshPublicBlob(privateKey: privateKey) == blob else { throw SSHAgentError.invalidKey }
            let signature = try crypto.sshSign(privateKey: privateKey, data: data, flags: flags)
            guard current() else { return Data([5]) }
            if accepted.remember, let grant {
                if grants.count < 128 { grants.insert(grant) }
                else {
                    errorMessage = "The remembered SSH approval limit was reached. This request was approved once. Lock the vault to clear approvals."
                    onChange?()
                }
            }
            logger.info("SSH signing request approved")
            return Data([14]) + SSHWire.string(signature)
        } catch {
            // Never log request bytes, signatures or private key parser details.
            logger.error("SSH request rejected")
            if let error = error as? SSHAgentError, error != .invalidPacket {
                errorMessage = error.localizedDescription
                onChange?()
            }
            return Data([5])
        }
    }
}
