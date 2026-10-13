import Foundation
import CryptoKit
import Security

/// OpenSSH PROTOCOL.agent session-bind@openssh.com verification. The host must
/// sign the session identifier; this proves key possession, not hostname trust.
/// All signature algorithms use Apple frameworks. No private keys are imported.
nonisolated struct SSHSessionBinding: Equatable {
    let hostKey: Data
    let session: Data
    let forwarded: Bool

    init(reader: inout SSHReader) throws {
        hostKey = try reader.string()
        session = try reader.string()
        let signature = try reader.string()
        let flag = try reader.byte()
        guard flag <= 1, (16...128).contains(session.count), hostKey.count <= 16_384,
              signature.count <= 16_384 else { throw SSHAgentError.invalidPacket }
        forwarded = flag == 1
        try reader.end()
        try Self.verify(host: hostKey, signature: signature, message: session)
    }

    private static func verify(host: Data, signature: Data, message: Data) throws {
        var keyReader = SSHReader(host), sigReader = SSHReader(signature)
        let type = try keyReader.text(), algorithm = try sigReader.text()
        let signatureBytes = try sigReader.string()
        try sigReader.end()
        if type == "ssh-ed25519" {
            let raw = try keyReader.string()
            try keyReader.end()
            guard algorithm == type, raw.count == 32, signatureBytes.count == 64,
                  try Curve25519.Signing.PublicKey(rawRepresentation: raw).isValidSignature(signatureBytes, for: message)
            else { throw SSHAgentError.invalidPacket }
            return
        }
        let keyBytes: Data
        let attributes: [CFString: Any]
        let verification: SecKeyAlgorithm
        var sig = signatureBytes
        if type == "ssh-rsa" {
            let e = try positiveInteger(&keyReader, maximum: 5)
            let n = try positiveInteger(&keyReader, maximum: 1025)
            try keyReader.end()
            guard (256...1025).contains(n.count) else { throw SSHAgentError.invalidPacket }
            keyBytes = der(0x30, der(2, n) + der(2, e))
            attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
            switch algorithm {
            case "rsa-sha2-256": verification = .rsaSignatureMessagePKCS1v15SHA256
            case "rsa-sha2-512": verification = .rsaSignatureMessagePKCS1v15SHA512
            default: throw SSHAgentError.invalidPacket
            }
            // SSH RSA signatures may omit leading zero octets (RFC 8332 §3).
            let width = n.count - (n.first == 0 ? 1 : 0)
            guard sig.count <= width else { throw SSHAgentError.invalidPacket }
            sig = Data(repeating: 0, count: width - sig.count) + sig
        } else if type.hasPrefix("ecdsa-sha2-") {
            let curve = try keyReader.text()
            keyBytes = try keyReader.string()
            try keyReader.end()
            let bits: Int, width: Int
            switch curve {
            case "nistp256": bits = 256; width = 65; verification = .ecdsaSignatureMessageX962SHA256
            case "nistp384": bits = 384; width = 97; verification = .ecdsaSignatureMessageX962SHA384
            case "nistp521": bits = 521; width = 133; verification = .ecdsaSignatureMessageX962SHA512
            default: throw SSHAgentError.invalidPacket
            }
            guard type == "ecdsa-sha2-" + curve, algorithm == type,
                  keyBytes.count == width, keyBytes.first == 4 else { throw SSHAgentError.invalidPacket }
            attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                          kSecAttrKeyClass: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits: bits]
            var integers = SSHReader(signatureBytes)
            let r = try positiveInteger(&integers, maximum: 67)
            let s = try positiveInteger(&integers, maximum: 67)
            try integers.end()
            sig = der(0x30, der(2, r) + der(2, s))
        } else { throw SSHAgentError.unsupportedKey }
        guard let publicKey = SecKeyCreateWithData(keyBytes as CFData, attributes as CFDictionary, nil),
              SecKeyIsAlgorithmSupported(publicKey, .verify, verification),
              SecKeyVerifySignature(publicKey, verification, message as CFData, sig as CFData, nil)
        else { throw SSHAgentError.invalidPacket }
    }

    // SSH mpint and DER INTEGER share signed big-endian integer bytes. Reject
    // negative, zero and noncanonical representations before passing to Apple.
    private static func positiveInteger(_ reader: inout SSHReader, maximum: Int) throws -> Data {
        let bytes = try reader.string()
        guard let first = bytes.first, bytes.count <= maximum, first & 0x80 == 0,
              first != 0 || (bytes.count > 1 && bytes[1] & 0x80 != 0)
        else { throw SSHAgentError.invalidPacket }
        return bytes
    }
    private static func der(_ tag: UInt8, _ value: Data) -> Data {
        let length: Data
        if value.count < 128 { length = Data([UInt8(value.count)]) }
        else if value.count <= 255 { length = Data([0x81, UInt8(value.count)]) }
        else { length = Data([0x82, UInt8(value.count >> 8), UInt8(truncatingIfNeeded: value.count)]) }
        return Data([tag]) + length + value
    }
}

nonisolated extension PrizmCryptoService {
    func sshSessionBinding(reader: inout SSHReader) throws -> SSHSessionBinding {
        try SSHSessionBinding(reader: &reader)
    }
}
