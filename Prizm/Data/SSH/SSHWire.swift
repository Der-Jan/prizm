import Foundation

nonisolated enum SSHAgentError: Error, LocalizedError, Equatable {
    case invalidPacket, unsupportedKey, invalidKey, locked, busy
    var errorDescription: String? {
        switch self {
        case .unsupportedKey: "Supported keys: unencrypted OpenSSH Ed25519 and PEM RSA."
        case .invalidKey: "SSH private and public keys do not match or are invalid."
        case .locked: "Unlock the vault to use the SSH agent."
        case .busy: "Another SSH approval is already pending."
        case .invalidPacket: "Invalid or unsupported SSH agent request."
        }
    }
}

nonisolated struct SSHReader {
    private let data: Data
    private var offset = 0
    init(_ data: Data) { self.data = Data(data) }
    mutating func byte() throws -> UInt8 {
        guard offset < data.count else { throw SSHAgentError.invalidPacket }
        defer { offset += 1 }
        return data[offset]
    }
    mutating func uint32() throws -> UInt32 {
        var result: UInt32 = 0
        for _ in 0..<4 { result = (result << 8) | UInt32(try byte()) }
        return result
    }
    mutating func string() throws -> Data {
        let count = Int(try uint32())
        guard count <= data.count - offset else { throw SSHAgentError.invalidPacket }
        defer { offset += count }
        return Data(data[offset..<offset + count])
    }
    mutating func text() throws -> String {
        guard let value = String(data: try string(), encoding: .utf8) else { throw SSHAgentError.invalidPacket }
        return value
    }
    mutating func end() throws {
        guard offset == data.count else { throw SSHAgentError.invalidPacket }
    }
}

nonisolated enum SSHWire {
    static let maximumPacket = 65_536
    static func uint32(_ value: UInt32) -> Data {
        Data([UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
              UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
    }
    static func string(_ data: Data) -> Data { uint32(UInt32(data.count)) + data }
    static func text(_ value: String) -> Data { string(Data(value.utf8)) }
    struct Authentication {
        let username: String
        let session: Data
        let hostKey: Data?
    }
    static func authentication(_ data: Data, key: Data, algorithm: String) throws -> String {
        try authenticationDetails(data, key: key, algorithm: algorithm).username
    }
    static func authenticationDetails(_ data: Data, key: Data, algorithm: String) throws -> Authentication {
        guard data.count <= 32_768 else { throw SSHAgentError.invalidPacket }
        var reader = SSHReader(data)
        let session = try reader.string()
        guard (16...128).contains(session.count), try reader.byte() == 50 else { throw SSHAgentError.invalidPacket }
        let user = try reader.text()
        guard !user.isEmpty, user.utf8.count <= 256,
              user.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
              try reader.text() == "ssh-connection" else { throw SSHAgentError.invalidPacket }
        let method = try reader.text()
        guard method == "publickey" || method == "publickey-hostbound-v00@openssh.com",
              try reader.byte() == 1, try reader.text() == algorithm,
              try reader.string() == key else { throw SSHAgentError.invalidPacket }
        var hostKey: Data?
        if method == "publickey-hostbound-v00@openssh.com" {
            // Structural validation only: this supplied host key is not a verified
            // destination or OpenSSH session binding, so the UI must not claim it is.
            hostKey = try reader.string()
            var host = SSHReader(hostKey!)
            let type = try host.text()
            if type == "ssh-ed25519" {
                guard try host.string().count == 32 else { throw SSHAgentError.invalidPacket }
            } else if type == "ssh-rsa" {
                let e = try host.string(), n = try host.string()
                guard (1...5).contains(e.count), (256...1025).contains(n.count) else { throw SSHAgentError.invalidPacket }
            } else if type.hasPrefix("ecdsa-sha2-") {
                let curve = try host.text(), point = try host.string()
                guard ["nistp256", "nistp384", "nistp521"].contains(curve),
                      type == "ecdsa-sha2-" + curve,
                      point.first == 4, [65, 97, 133].contains(point.count) else { throw SSHAgentError.invalidPacket }
            } else { throw SSHAgentError.invalidPacket }
            try host.end()
        }
        try reader.end()
        return Authentication(username: user, session: session, hostKey: hostKey)
    }
}
