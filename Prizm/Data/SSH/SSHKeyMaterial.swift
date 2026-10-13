import Foundation
import CryptoKit
import Security

/// SSH encoding/parsing only; signatures use CryptoKit Ed25519 (RFC 8709) or
/// Security.framework RSA PKCS#1 v1.5 with SHA-2 (RFC 8332). No persistent key
/// import, external crypto, subprocess, or private-key file. Swift Data/String
/// CoW and Apple's key handles cannot guarantee complete memory zeroization.
nonisolated enum SSHKeyMaterial {
    case ed25519(Curve25519.Signing.PrivateKey)
    case rsa(SecKey)

    init(privateKey: String) throws {
        guard privateKey.utf8.count <= 128_000 else { throw SSHAgentError.invalidKey }
        if privateKey.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            var bytes = try Self.decodePEM(privateKey, label: "OPENSSH PRIVATE KEY")
            defer { bytes.resetBytes(in: bytes.indices) }
            let magic = Data("openssh-key-v1\0".utf8)
            guard bytes.starts(with: magic) else { throw SSHAgentError.invalidKey }
            var reader = SSHReader(Data(bytes.dropFirst(magic.count)))
            guard try reader.text() == "none", try reader.text() == "none",
                  try reader.string().isEmpty, try reader.uint32() == 1 else { throw SSHAgentError.unsupportedKey }
            let publicBlob = try reader.string()
            var secret = try reader.string()
            defer { secret.resetBytes(in: secret.indices) }
            try reader.end()
            var inner = SSHReader(secret)
            guard try inner.uint32() == inner.uint32(), try inner.text() == "ssh-ed25519" else { throw SSHAgentError.unsupportedKey }
            let publicBytes = try inner.string()
            var privateBytes = try inner.string()
            defer { privateBytes.resetBytes(in: privateBytes.indices) }
            guard publicBytes.count == 32, privateBytes.count == 64,
                  Data(privateBytes.suffix(32)) == publicBytes else { throw SSHAgentError.invalidKey }
            let comment = try inner.string()
            guard comment.count <= 1024 else { throw SSHAgentError.invalidKey }
            // openssh-key-v1 plaintext is padded to an 8-byte boundary, with 1,2,... .
            guard secret.count % 8 == 0 else { throw SSHAgentError.invalidKey }
            var padding: UInt8 = 1
            while let byte = try? inner.byte() {
                guard padding <= 8, byte == padding else { throw SSHAgentError.invalidKey }
                padding += 1
            }
            guard padding > 1 else { throw SSHAgentError.invalidKey }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(privateBytes.prefix(32)))
            guard key.publicKey.rawRepresentation == publicBytes,
                  publicBlob == SSHWire.text("ssh-ed25519") + SSHWire.string(publicBytes) else { throw SSHAgentError.invalidKey }
            self = .ed25519(key)
        } else {
            // SecItemImport with a nil keychain creates an in-memory key only.
            guard privateKey.contains("-----BEGIN RSA PRIVATE KEY-----") || privateKey.contains("-----BEGIN PRIVATE KEY-----"),
                  !privateKey.contains("ENCRYPTED") else { throw SSHAgentError.unsupportedKey }
            var bytes = Data(privateKey.utf8)
            defer { bytes.resetBytes(in: bytes.indices) }
            var format = SecExternalFormat.formatUnknown
            var type = SecExternalItemType.itemTypePrivateKey
            var items: CFArray?
            var parameters = SecItemImportExportKeyParameters()
            parameters.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
            parameters.flags = [.noAccessControl]
            guard SecItemImport(bytes as CFData, nil, &format, &type, [], &parameters, nil, &items) == errSecSuccess,
                  let imported = items as? [SecKey], imported.count == 1 else { throw SSHAgentError.invalidKey }
            let key = imported[0]
            let attributes = SecKeyCopyAttributes(key) as NSDictionary?
            guard attributes?[kSecAttrKeyType] as? String == kSecAttrKeyTypeRSA as String,
                  let bits = attributes?[kSecAttrKeySizeInBits] as? Int,
                  (2048...8192).contains(bits) else { throw SSHAgentError.unsupportedKey }
            self = .rsa(key)
        }
    }

    var publicBlob: Data {
        get throws {
            switch self {
            case .ed25519(let key):
                return SSHWire.text("ssh-ed25519") + SSHWire.string(key.publicKey.rawRepresentation)
            case .rsa(let key):
                guard let publicKey = SecKeyCopyPublicKey(key),
                      let bytes = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else { throw SSHAgentError.invalidKey }
                var root = SSHDER(bytes)
                var sequence = SSHDER(try root.value(tag: 0x30))
                try root.end()
                let n = try sequence.value(tag: 2), e = try sequence.value(tag: 2)
                try sequence.end()
                return SSHWire.text("ssh-rsa") + SSHWire.string(e) + SSHWire.string(n)
            }
        }
    }

    func sign(_ data: Data, flags: UInt32) throws -> Data {
        let name: String
        let signature: Data
        switch self {
        case .ed25519(let key):
            guard flags == 0 else { throw SSHAgentError.invalidPacket }
            name = "ssh-ed25519"
            signature = try key.signature(for: data)
        case .rsa(let key):
            let algorithm: SecKeyAlgorithm
            switch flags {
            case 2: name = "rsa-sha2-256"; algorithm = .rsaSignatureMessagePKCS1v15SHA256
            case 4: name = "rsa-sha2-512"; algorithm = .rsaSignatureMessagePKCS1v15SHA512
            default: throw SSHAgentError.invalidPacket
            }
            guard let result = SecKeyCreateSignature(key, algorithm, data as CFData, nil) as Data? else { throw SSHAgentError.invalidKey }
            signature = result
        }
        return SSHWire.text(name) + SSHWire.string(signature)
    }

    private static func decodePEM(_ text: String, label: String) throws -> Data {
        let start = "-----BEGIN \(label)-----", end = "-----END \(label)-----"
        guard let a = text.range(of: start), let b = text.range(of: end), a.upperBound < b.lowerBound,
              text[..<a.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              text[b.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let data = Data(base64Encoded: text[a.upperBound..<b.lowerBound].filter { !$0.isWhitespace }) else { throw SSHAgentError.invalidKey }
        return data
    }
}

/// Minimal DER framing for RSA public integers exported by Security.framework.
nonisolated private struct SSHDER {
    var reader: SSHReader
    init(_ data: Data) { reader = SSHReader(data) }
    mutating func value(tag: UInt8) throws -> Data {
        guard try reader.byte() == tag else { throw SSHAgentError.invalidKey }
        let first = try reader.byte()
        var count = Int(first)
        if first >= 128 {
            let width = Int(first & 127)
            guard (1...3).contains(width) else { throw SSHAgentError.invalidKey }
            count = 0
            for _ in 0..<width { count = (count << 8) | Int(try reader.byte()) }
        }
        guard count <= 16_384 else { throw SSHAgentError.invalidKey }
        var result = Data()
        for _ in 0..<count { result.append(try reader.byte()) }
        return result
    }
    mutating func end() throws { try reader.end() }
}

nonisolated extension PrizmCryptoService {
    func sshPublicBlob(privateKey: String) throws -> Data {
        try SSHKeyMaterial(privateKey: privateKey).publicBlob
    }
    func sshSign(privateKey: String, data: Data, flags: UInt32) throws -> Data {
        try SSHKeyMaterial(privateKey: privateKey).sign(data, flags: flags)
    }
    func sshFingerprint(_ blob: Data) -> String {
        "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}
