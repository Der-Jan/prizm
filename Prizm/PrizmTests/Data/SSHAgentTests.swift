import XCTest
@testable import Prizm

final class SSHAgentTests: XCTestCase {
    func testReaderRejectsTruncatedStringsAndTrailingBytes() throws {
        var reader = SSHReader(Data([0, 0, 0, 4, 1]))
        XCTAssertThrowsError(try reader.string())
        var trailing = SSHReader(Data([11, 0]))
        XCTAssertEqual(try trailing.byte(), 11)
        XCTAssertThrowsError(try trailing.end())
    }

    func testAuthPayloadRejectsUnrelatedSigning() {
        XCTAssertThrowsError(try SSHWire.authentication(Data("arbitrary input".utf8), key: Data(), algorithm: "ssh-ed25519"))
    }

    func testHostboundAuthenticationAcceptsEncodedHostKey() throws {
        let key = Data([1, 2, 3])
        let host = SSHWire.text("ssh-ed25519") + SSHWire.string(Data(repeating: 1, count: 32))
        let payload = SSHWire.string(Data(repeating: 1, count: 32)) + Data([50])
            + SSHWire.text("test-user") + SSHWire.text("ssh-connection")
            + SSHWire.text("publickey-hostbound-v00@openssh.com") + Data([1])
            + SSHWire.text("ssh-ed25519") + SSHWire.string(key) + SSHWire.string(host)
        XCTAssertEqual(try SSHWire.authentication(payload, key: key, algorithm: "ssh-ed25519"), "test-user")
        XCTAssertThrowsError(try SSHWire.authentication(payload.dropLast(), key: key, algorithm: "ssh-ed25519"))
    }

    func testAuthPayloadChecksExactKeyAndAlgorithm() throws {
        let key = Data([1, 2, 3])
        let payload = SSHWire.string(Data(repeating: 1, count: 32)) + Data([50])
            + SSHWire.text("test-user") + SSHWire.text("ssh-connection")
            + SSHWire.text("publickey") + Data([1]) + SSHWire.text("ssh-ed25519") + SSHWire.string(key)
        XCTAssertEqual(try SSHWire.authentication(payload, key: key, algorithm: "ssh-ed25519"), "test-user")
        XCTAssertThrowsError(try SSHWire.authentication(payload, key: Data([4]), algorithm: "ssh-ed25519"))
        XCTAssertThrowsError(try SSHWire.authentication(payload, key: key, algorithm: "rsa-sha2-256"))
        XCTAssertThrowsError(try SSHWire.authentication(payload + Data([0]), key: key, algorithm: "ssh-ed25519"))
    }
}

import CryptoKit
import Security
import Darwin

private enum SSHTestKey {
    // RFC 8032 section 7.1 test 1: public, non-production test key.
    static let seed = Data([0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
                            0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60])
    static func ed() throws -> (pem: String, blob: Data) {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let pub = key.publicKey.rawRepresentation
        let blob = SSHWire.text("ssh-ed25519") + SSHWire.string(pub)
        var inner = SSHWire.uint32(7) + SSHWire.uint32(7) + SSHWire.text("ssh-ed25519")
            + SSHWire.string(pub) + SSHWire.string(seed + pub) + SSHWire.text("test-only")
        let padding = 8 - inner.count % 8
        inner += Data((1...padding).map { UInt8($0) })
        let raw = Data("openssh-key-v1\0".utf8) + SSHWire.text("none") + SSHWire.text("none")
            + SSHWire.string(Data()) + SSHWire.uint32(1) + SSHWire.string(blob) + SSHWire.string(inner)
        return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + raw.base64EncodedString() + "\n-----END OPENSSH PRIVATE KEY-----", blob)
    }
    static func auth(_ blob: Data) -> Data {
        SSHWire.string(Data(repeating: 1, count: 32)) + Data([50]) + SSHWire.text("test-user")
            + SSHWire.text("ssh-connection") + SSHWire.text("publickey") + Data([1])
            + SSHWire.text("ssh-ed25519") + SSHWire.string(blob)
    }
    static func request(_ blob: Data) -> Data {
        Data([13]) + SSHWire.string(blob) + SSHWire.string(auth(blob)) + SSHWire.uint32(0)
    }
}

extension SSHAgentTests {
    func testEd25519OpenSSHImportAndRFC8032Signature() throws {
        let fixture = try SSHTestKey.ed()
        let key = try SSHKeyMaterial(privateKey: fixture.pem)
        XCTAssertEqual(try key.publicBlob, fixture.blob)
        var reply = SSHReader(try key.sign(Data(), flags: 0))
        XCTAssertEqual(try reply.text(), "ssh-ed25519")
        let signature = try reply.string()
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: SSHTestKey.seed).publicKey
        XCTAssertEqual(publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined(),
                       "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        // CryptoKit uses randomized Ed25519 signing. Validate generated signatures,
        // and independently verify the published deterministic RFC 8032 vector.
        XCTAssertTrue(publicKey.isValidSignature(signature, for: Data()))
        let hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        let golden = Data(stride(from: 0, to: hex.count, by: 2).map { i in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return UInt8(hex[a..<hex.index(a, offsetBy: 2)], radix: 16)!
        })
        XCTAssertTrue(publicKey.isValidSignature(golden, for: Data()))
        XCTAssertThrowsError(try key.sign(Data(), flags: 2))
        XCTAssertThrowsError(try SSHKeyMaterial(privateKey: fixture.pem + "trailing data"))
        XCTAssertThrowsError(try SSHKeyMaterial(privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nAA==\n-----END OPENSSH PRIVATE KEY-----"))
    }

    func testSocketDoesNotReplaceExistingFileOrSymlink() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("socket").path
        try Data("keep".utf8).write(to: URL(fileURLWithPath: path))
        let server = SSHAgentSocket(path: path) { _, _ in Data([5]) }
        XCTAssertThrowsError(try server.start())
        server.stop()
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), Data("keep".utf8))
        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: "missing")
        XCTAssertThrowsError(try server.start())
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: path), "missing")
    }

    func testSocketPermissionsAndIdempotentCleanup() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let server = SSHAgentSocket(path: path) { _, _ in Data([5]) }
        try server.start()
        var entry = stat()
        XCTAssertEqual(lstat(path, &entry), 0)
        XCTAssertEqual(entry.st_mode & 0o777, 0o600)
        server.stop()
        server.stop()
        XCTAssertNotEqual(lstat(path, &entry), 0)
    }
}

@MainActor
final class SSHAgentLifecycleTests: XCTestCase {
    private func setupAgent(socketPath: String? = nil, timeout: Duration = .seconds(45), reprompt: Int = 0, deleted: Bool = false, additionalItems: [VaultItem] = []) async throws -> (SSHAgentManager, Data, UserDefaults) {
        let key = try SSHTestKey.ed()
        let vault = MockVaultRepository()
        let content = SSHKeyContent(privateKey: key.pem,
                                   publicKey: "ssh-ed25519 " + key.blob.base64EncodedString(),
                                   keyFingerprint: nil, notes: nil, customFields: [])
        let item = VaultItem(id: "test", name: "Test SSH", isFavorite: false, isDeleted: deleted,
                             creationDate: Date(), revisionDate: Date(), content: .sshKey(content), reprompt: reprompt)
        await vault.populate(items: [item] + additionalItems, folders: [], organizations: [], collections: [], syncedAt: Date())
        let defaults = UserDefaults(suiteName: UUID().uuidString)!
        let path = socketPath ?? FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let agent = SSHAgentManager(vault: vault, crypto: MockPrizmCryptoService(), defaults: defaults, approvalTimeout: timeout, socketPath: path)
        agent.setEnabled(true)
        XCTAssertTrue(agent.enabled)
        return (agent, key.blob, defaults)
    }

    private func pendingApproval(_ agent: SSHAgentManager) async throws -> SSHApproval {
        for _ in 0..<200 {
            if let request = agent.approval { return request }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw NSError(domain: "Missing approval", code: 1)
    }

    func testLockAndDisableInvalidatePendingSigning() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        let lockedReply = await agent.handle(Data([11]))
        XCTAssertEqual(lockedReply, Data([5]))
        agent.setVaultUnlocked(true)
        let task = Task { await agent.handle(SSHTestKey.request(blob)) }
        let request = try await pendingApproval(agent)
        agent.setVaultUnlocked(false)
        agent.respond(to: request.id, allow: true)
        let reply = await task.value
        XCTAssertEqual(reply, Data([5]))
        XCTAssertNil(agent.approval)
        agent.setVaultUnlocked(true)
        let second = Task { await agent.handle(SSHTestKey.request(blob)) }
        _ = try await pendingApproval(agent)
        agent.setEnabled(false)
        let disabled = await second.value
        XCTAssertEqual(disabled, Data([5]))
    }

    func testDeniedApprovedAndCancelledRequests() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let denied = Task { await agent.handle(SSHTestKey.request(blob)) }
        let denial = try await pendingApproval(agent)
        agent.respond(to: denial.id, allow: false)
        let deniedReply = await denied.value
        XCTAssertEqual(deniedReply, Data([5]))
        let allowed = Task { await agent.handle(SSHTestKey.request(blob)) }
        let approval = try await pendingApproval(agent)
        agent.respond(to: approval.id, allow: true)
        var reply = SSHReader(await allowed.value)
        XCTAssertEqual(try reply.byte(), 14)
        var signature = SSHReader(try reply.string())
        XCTAssertEqual(try signature.text(), "ssh-ed25519")
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: SSHTestKey.seed).publicKey
        XCTAssertTrue(publicKey.isValidSignature(try signature.string(), for: SSHTestKey.auth(blob)))
        let cancelled = Task { await agent.handle(SSHTestKey.request(blob)) }
        _ = try await pendingApproval(agent)
        cancelled.cancel()
        let cancelledReply = await cancelled.value
        XCTAssertEqual(cancelledReply, Data([5]))
        XCTAssertNil(agent.approval)
    }
    func testCorruptVaultKeyDoesNotBlockValidKeys() async throws {
        let key = try SSHTestKey.ed()
        let corrupt = VaultItem(id: "corrupt", name: "Corrupt SSH", isFavorite: false, isDeleted: false,
                                creationDate: Date(), revisionDate: Date(),
                                content: .sshKey(SSHKeyContent(privateKey: key.pem, publicKey: "ssh-ed25519 AA==",
                                                              keyFingerprint: nil, notes: nil, customFields: [])))
        let (agent, blob, _) = try await setupAgent(additionalItems: [corrupt])
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        var reply = SSHReader(await agent.handle(Data([11])))
        XCTAssertEqual(try reply.byte(), 12)
        XCTAssertEqual(try reply.uint32(), 1)
        XCTAssertEqual(try reply.string(), blob)
        XCTAssertNotNil(agent.errorMessage)
        let signing = Task { await agent.handle(SSHTestKey.request(blob)) }
        let request = try await pendingApproval(agent)
        agent.respond(to: request.id, allow: false)
        let denied = await signing.value
        XCTAssertEqual(denied, Data([5]))
    }

    func testProtectedAndDeletedKeysAreNotListed() async throws {
        for (reprompt, deleted) in [(1, false), (0, true)] {
            let (agent, _, _) = try await setupAgent(reprompt: reprompt, deleted: deleted)
            agent.setVaultUnlocked(true)
            let reply = await agent.handle(Data([11]))
            XCTAssertEqual(reply, Data([12, 0, 0, 0, 0]))
            agent.setEnabled(false)
        }
    }

    func testApprovalPresentationAndStateRefresh() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        let viewModel = SSHAgentViewModel(manager: agent)
        var presented = 0
        viewModel.presentApproval = { presented += 1 }
        agent.setVaultUnlocked(true)
        let request = Task { await agent.handle(SSHTestKey.request(blob)) }
        _ = try await pendingApproval(agent)
        XCTAssertEqual(presented, 1)
        XCTAssertNotNil(viewModel.approval)
        agent.setVaultUnlocked(false)
        let reply = await request.value
        XCTAssertEqual(reply, Data([5]))
        XCTAssertNil(viewModel.approval)
    }

    func testApprovalTimesOutAndRejectsUnsolicitedReply() async throws {
        let (agent, blob, _) = try await setupAgent(timeout: .milliseconds(30))
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let request = Task { await agent.handle(SSHTestKey.request(blob)) }
        _ = try await pendingApproval(agent)
        agent.respond(to: UUID(), allow: true)
        let reply = await request.value
        XCTAssertEqual(reply, Data([5]))
        XCTAssertNil(agent.approval)
    }

    func testClientDisconnectCancelsApproval() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            agent.socketPath.utf8CString.withUnsafeBytes { buffer.copyBytes(from: $0) }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        XCTAssertEqual(connected, 0)
        let packet = SSHWire.string(SSHTestKey.request(blob))
        let sent = packet.withUnsafeBytes { send(fd, $0.baseAddress!, packet.count, 0) }
        XCTAssertEqual(sent, packet.count)
        _ = try await pendingApproval(agent)
        close(fd)
        for _ in 0..<200 {
            if agent.approval == nil { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertNil(agent.approval)
    }

    func testSignedContainerSocketWithExternalOpenSSHClient() async throws {
        guard ProcessInfo.processInfo.environment["PRIZM_SSH_SIGNED_SOCKET_TEST"] == "1" else {
            throw XCTSkip("Opt-in signed sandbox test with external OpenSSH runner")
        }
        let run = try XCTUnwrap(ProcessInfo.processInfo.environment["PRIZM_SSH_TEST_RUN_ID"])
        guard run.utf8.count == 8, run.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw NSError(domain: "Invalid SSH integration run ID", code: 1)
        }
        let prefix = NSHomeDirectory() + "/.ssh-test-" + run
        let path = prefix + ".sock"
        let ready = URL(fileURLWithPath: prefix + "-ready")
        let marker = URL(fileURLWithPath: prefix + "-complete")
        if FileManager.default.fileExists(atPath: marker.path) { try FileManager.default.removeItem(at: marker) }
        let (agent, _, _) = try await setupAgent(socketPath: path)
        defer {
            agent.onChange = nil
            agent.setEnabled(false)
            try? FileManager.default.removeItem(at: marker)
            try? FileManager.default.removeItem(at: ready)
        }
        agent.setVaultUnlocked(true)
        var approvals = 0
        var boundApprovals = 0
        // This auto-approver exists only in this explicitly opted-in test, with
        // the published RFC key in a mock vault; production always asks the user.
        agent.onChange = {
            if let request = agent.approval {
                approvals += 1
                if request.hostFingerprint != nil { boundApprovals += 1 }
                agent.respond(to: request.id, allow: true, rememberUntilLock: request.hostFingerprint != nil)
            }
        }
        try Data("ready".utf8).write(to: ready)
        for _ in 0..<300 {
            if FileManager.default.fileExists(atPath: marker.path) { break }
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertEqual(try String(contentsOf: marker, encoding: .utf8), "verified")
        XCTAssertEqual(approvals, 2)
        XCTAssertEqual(boundApprovals, 1)
    }

}

private enum SSHRSAFixture {
    // Ephemeral RSA-2048 key generated for this test; never used for authentication.
    static let pem = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs2ept0PThBXKoIX56NkWJf+z4ooiMY2mntLcMR/uTI39qU6p
lfftUu6CSgXOWv7uyiCbEo9jUzrnJMQ2GWZwYyAnRO9/BclzwMhC6Xc1h6epVVBY
Yk33BfXVDj45fHbkbJPbecQfNEyt/p1/wrqruyGaSKctfdqI4E+pIuwUBz80nbNa
gNC00n2Qj4TLmLwavdQ2RYIEb5qvWfbO8pnL7XIQIxcjvYdvq5l2Civvlnuorx2x
WTyYg2TRxVoSnyumo7ZgrywKKhY8bn157UdV7UdpgmAsAwgTehlGiVQdmOckmfYF
qjAMuHZsQGbEqzxoTTUFKGnNpO6V5eRQgPSLswIDAQABAoIBAFwq5IkPYmoYW+oO
Cm7yoCtTa5H1z01P7Yro31Cpi95ukCPcEsnF/nm9qNfolbQwBnN3PtPRMIEA4OEF
oJl6BEEYsrP6qnJJpZskByQ0Jx8TJq56wX13enHoctWHaDcmSYHykC3FcRaIUldd
iNZ82l8gC0hKAtgGXo2Gv2j+ieeSV/fhgA/3qebEBUlrBapC17uFZTKoFYLvCGT0
u+wciINbXSj57s6XuSTZjYe4zQGvy2buGPRPODMwRu0A0WDSAFCcR4UVQoBiMfIa
8Gzc+zO6OyuGXX2B3OAl8ueXZXTRCSVdoBGH9UZ2mt9jyHXKKJ2G+yk2E+Uru5TK
l2V4wEkCgYEA2VjdAUAr7ZoXkExcsXjOMOzHo9yd3v1XjtHr5t0y2Ae6wDIzmKBG
OikeAXfpmIvey8gco8aptO4uU/53C/M9+9uynvJMfDVPP+5vGcqTrc/cgjeI+5pF
c6g5NIqzcFdUNCj3kcnyzn/jjE4r2YN2JOW5SdDBzR0pGIiNQtr8Ih8CgYEA009o
/Sf67wdTk9d1kqMRy0NjeUPIx73SLPKqIYlMPqXDt5agtfxtOjBl29Ta56uWJ+9k
/lElGWG0HUeTrmvZ80xXHq3tNLHO/YBoIzvKPvoS03rKlxBrvpslqBEtf+ZppS/p
Cb77StbolfMbbxQEG0aUKAolIYcBnppTbM/6a+0CgYBVENSe0rDes7qZPWniA/gf
aezRE12uktUcDskXeGeX6Z6L7poHGGOkC8e0p2wDymqOs2mSKATvzXDQav3I7ZDK
7DfCwe5xhqPXz8gn/gNCueICDR5N6xlXpPWOvOJyC5vnNkl/A91GOQOkPEwpO6yX
0FlurIfNcaZN9dPj4LVh3QKBgQCttwmznMuA97/wuV8xppd5R7QeO+hytI11YCUX
Ht0sX2/vnIgQNC3DeYgzWeCANiJiQD8Bh8n8/MJqk65H5OgvSKISWZ+5AzgMVSTH
Wl7guQsDCl5EJD6/WqJxcXW7QLu3DhUBax0BIH3i0BHMlmLt3W7tH7H4xxlAvtQ4
jx3q3QKBgQCNqNtCHhkioWqbCrno7jwqrZaPHrWiRiQFKW8gxiTv83lXa4Ost0HK
eggwUzwzjYClvdlpBwB+Q2Dztb9N5PVt6PbczksUiTmjLQJ3N3ToGOJbztjgE1yt
pdlTQdNHeFKwp2i3YjoTR1cHNZ3VvVyNEoj6FHu5ZYQsDE62k/Vo3g==
-----END RSA PRIVATE KEY-----
"""
}

extension SSHAgentTests {
    func testRSAPEMSHA2SignaturesAreVerifiedBySecurityFramework() throws {
        let material = try SSHKeyMaterial(privateKey: SSHRSAFixture.pem)
        let message = Data("test-only SSH signing".utf8)
        let blob = try material.publicBlob
        var identity = SSHReader(blob)
        XCTAssertEqual(try identity.text(), "ssh-rsa")
        var format = SecExternalFormat.formatUnknown
        var type = SecExternalItemType.itemTypePrivateKey
        var items: CFArray?
        XCTAssertEqual(SecItemImport(Data(SSHRSAFixture.pem.utf8) as CFData, nil, &format, &type, [], nil, nil, &items), errSecSuccess)
        let key = try XCTUnwrap((items as? [SecKey])?.first)
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
        for (flag, name, algorithm) in [(UInt32(2), "rsa-sha2-256", SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256),
                                        (UInt32(4), "rsa-sha2-512", SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512)] {
            var signature = SSHReader(try material.sign(message, flags: flag))
            XCTAssertEqual(try signature.text(), name)
            XCTAssertTrue(SecKeyVerifySignature(publicKey, algorithm, message as CFData, try signature.string() as CFData, nil))
        }
        XCTAssertThrowsError(try material.sign(message, flags: 0))
        XCTAssertThrowsError(try material.sign(message, flags: 6))
    }
}


extension SSHAgentTests {
    func testSlowFrameCannotExtendReadDeadline() async throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let server = SSHAgentSocket(path: path, ioTimeout: 0.2) { _, _ in Data([5]) }
        try server.start()
        defer { server.stop() }
        let client = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(client, 0)
        defer { close(client) }
        var noSignal: Int32 = 1
        XCTAssertEqual(setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)), 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            path.utf8CString.withUnsafeBytes { buffer.copyBytes(from: $0) }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        XCTAssertEqual(connected, 0)
        var byte: UInt8 = 0
        XCTAssertEqual(send(client, &byte, 1, 0), 1)
        try await Task.sleep(for: .milliseconds(100))
        _ = send(client, &byte, 1, 0)
        try await Task.sleep(for: .milliseconds(150))
        // Receiving another byte cannot renew the overall frame budget.
        var readable = pollfd(fd: client, events: Int16(POLLIN), revents: 0)
        let result = poll(&readable, 1, 500)
        XCTAssertGreaterThan(result, 0, "Slow partial frame must be disconnected within its absolute deadline")
        if result > 0 { XCTAssertEqual(recv(client, &byte, 1, MSG_DONTWAIT), 0) }
    }
}

// Session binding fixtures contain generated, non-production host keys only.
private enum SSHBindingFixture {
    static func packet(key: Curve25519.Signing.PrivateKey, session: Data, forwarded: Bool = false) throws -> Data {
        let host = SSHWire.text("ssh-ed25519") + SSHWire.string(key.publicKey.rawRepresentation)
        let signature = SSHWire.text("ssh-ed25519") + SSHWire.string(try key.signature(for: session))
        return Data([27]) + SSHWire.text("session-bind@openssh.com") + SSHWire.string(host)
            + SSHWire.string(session) + SSHWire.string(signature) + Data([forwarded ? 1 : 0])
    }
}

extension SSHAgentLifecycleTests {
    func testSessionBindingVerifiesSignatureAndRejectsRebinding() async throws {
        let (agent, _, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let host = Curve25519.Signing.PrivateKey()
        let session = Data(repeating: 1, count: 32)
        let packet = try SSHBindingFixture.packet(key: host, session: session)
        let connection = UUID()
        var tampered = packet
        tampered[tampered.count - 2] ^= 1
        let invalid = await agent.handle(tampered, connectionID: UUID())
        XCTAssertEqual(invalid, Data([28]))
        let valid = await agent.handle(packet, connectionID: connection)
        XCTAssertEqual(valid, Data([6]))
        let rebound = await agent.handle(packet, connectionID: connection)
        XCTAssertEqual(rebound, Data([28]))
        let separate = await agent.handle(packet, connectionID: UUID())
        XCTAssertEqual(separate, Data([6]))
        let trailing = await agent.handle(packet + Data([0]), connectionID: UUID())
        XCTAssertEqual(trailing, Data([28]))
    }

    func testBindingRejectsDifferentSigningSessionBeforeApproval() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let connection = UUID()
        let packet = try SSHBindingFixture.packet(key: Curve25519.Signing.PrivateKey(), session: Data(repeating: 2, count: 32))
        let bound = await agent.handle(packet, connectionID: connection)
        XCTAssertEqual(bound, Data([6]))
        let signing = Task { await agent.handle(SSHTestKey.request(blob), connectionID: connection) }
        try await Task.sleep(for: .milliseconds(50))
        XCTAssertNil(agent.approval)
        if let approval = agent.approval { agent.respond(to: approval.id, allow: false) }
        let reply = await signing.value
        XCTAssertEqual(reply, Data([5]))
    }
}

extension SSHAgentLifecycleTests {
    func testRememberedApprovalRequiresFreshBindingAndClearsOnLock() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let host = Curve25519.Signing.PrivateKey()
        let session = Data(repeating: 1, count: 32)
        let first = UUID()
        let binding = try SSHBindingFixture.packet(key: host, session: session)
        let bound = await agent.handle(binding, connectionID: first)
        XCTAssertEqual(bound, Data([6]))
        let initial = Task { await agent.handle(SSHTestKey.request(blob), connectionID: first) }
        let approval = try await pendingApproval(agent)
        XCTAssertNotNil(approval.hostFingerprint)
        agent.respond(to: approval.id, allow: true, rememberUntilLock: true)
        let signed = await initial.value
        XCTAssertEqual(signed.first, 14)
        let second = UUID()
        let freshSession = Data(repeating: 3, count: 32)
        let freshBinding = try SSHBindingFixture.packet(key: host, session: freshSession)
        let freshBound = await agent.handle(freshBinding, connectionID: second)
        XCTAssertEqual(freshBound, Data([6]))
        var auth = SSHTestKey.auth(blob)
        auth.replaceSubrange(4..<36, with: freshSession)
        let packet = Data([13]) + SSHWire.string(blob) + SSHWire.string(auth) + SSHWire.uint32(0)
        let subsequent = Task { await agent.handle(packet, connectionID: second) }
        try await Task.sleep(for: .milliseconds(50))
        XCTAssertNil(agent.approval)
        if let request = agent.approval { agent.respond(to: request.id, allow: false) }
        let reused = await subsequent.value
        XCTAssertEqual(reused.first, 14)
        // A different host key never inherits a remembered approval.
        let third = UUID()
        let different = try SSHBindingFixture.packet(key: Curve25519.Signing.PrivateKey(), session: session)
        _ = await agent.handle(different, connectionID: third)
        let changed = Task { await agent.handle(SSHTestKey.request(blob), connectionID: third) }
        let changedApproval = try await pendingApproval(agent)
        agent.respond(to: changedApproval.id, allow: false)
        let denied = await changed.value
        XCTAssertEqual(denied, Data([5]))
        // Lock invalidates the cached grant and all connection bindings.
        agent.setVaultUnlocked(false)
        agent.setVaultUnlocked(true)
        let fourth = UUID()
        _ = await agent.handle(binding, connectionID: fourth)
        let afterLock = Task { await agent.handle(SSHTestKey.request(blob), connectionID: fourth) }
        let again = try await pendingApproval(agent)
        agent.respond(to: again.id, allow: false)
        let cleared = await afterLock.value
        XCTAssertEqual(cleared, Data([5]))
    }
}

extension SSHAgentTests {
    func testSessionBindingRSAAndAllNISTCurves() throws {
        let session = Data(repeating: 7, count: 32)
        func verify(host: Data, algorithm: String, signature: Data) throws {
            let wire = SSHWire.string(host) + SSHWire.string(session)
                + SSHWire.string(SSHWire.text(algorithm) + SSHWire.string(signature)) + Data([0])
            var reader = SSHReader(wire)
            XCTAssertEqual(try SSHSessionBinding(reader: &reader).session, session)
            var corrupted = wire
            corrupted[corrupted.count - 2] ^= 1
            var invalid = SSHReader(corrupted)
            XCTAssertThrowsError(try SSHSessionBinding(reader: &invalid))
        }
        let rsa = try SSHKeyMaterial(privateKey: SSHRSAFixture.pem)
        for flag: UInt32 in [2, 4] {
            var signature = SSHReader(try rsa.sign(session, flags: flag))
            try verify(host: rsa.publicBlob, algorithm: signature.text(), signature: signature.string())
        }
        func mpint(_ bytes: Data) -> Data {
            let stripped = Data(bytes.drop(while: { $0 == 0 }))
            return SSHWire.string(stripped.first.map { $0 & 128 != 0 } == true ? Data([0]) + stripped : stripped)
        }
        func ecc(curve: String, publicKey: Data, signature: Data) throws {
            let algorithm = "ecdsa-sha2-" + curve
            let width = signature.count / 2
            try verify(host: SSHWire.text(algorithm) + SSHWire.text(curve) + SSHWire.string(publicKey),
                       algorithm: algorithm, signature: mpint(Data(signature.prefix(width))) + mpint(Data(signature.suffix(width))))
        }
        let p256 = P256.Signing.PrivateKey()
        try ecc(curve: "nistp256", publicKey: p256.publicKey.x963Representation, signature: p256.signature(for: session).rawRepresentation)
        let p384 = P384.Signing.PrivateKey()
        try ecc(curve: "nistp384", publicKey: p384.publicKey.x963Representation, signature: p384.signature(for: session).rawRepresentation)
        let p521 = P521.Signing.PrivateKey()
        try ecc(curve: "nistp521", publicKey: p521.publicKey.x963Representation, signature: p521.signature(for: session).rawRepresentation)
    }
}

extension SSHAgentLifecycleTests {
    func testForwardingChainAndHostboundMismatch() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let connection = UUID()
        let jump = Curve25519.Signing.PrivateKey(), destination = Curve25519.Signing.PrivateKey()
        let first = try SSHBindingFixture.packet(key: jump, session: Data(repeating: 9, count: 32), forwarded: true)
        let last = try SSHBindingFixture.packet(key: destination, session: Data(repeating: 1, count: 32))
        let forward = await agent.handle(first, connectionID: connection)
        XCTAssertEqual(forward, Data([6]))
        let duplicate = await agent.handle(first, connectionID: connection)
        XCTAssertEqual(duplicate, Data([6]))
        let final = await agent.handle(last, connectionID: connection)
        XCTAssertEqual(final, Data([6]))
        let signing = Task { await agent.handle(SSHTestKey.request(blob), connectionID: connection) }
        let approval = try await pendingApproval(agent)
        XCTAssertEqual(approval.forwardingHostFingerprints.count, 1)
        XCTAssertNotNil(approval.hostFingerprint)
        agent.respond(to: approval.id, allow: true, rememberUntilLock: true)
        let result = await signing.value
        XCTAssertEqual(result.first, 14)
        let wrongHost = SSHWire.text("ssh-ed25519") + SSHWire.string(jump.publicKey.rawRepresentation)
        let auth = SSHWire.string(Data(repeating: 1, count: 32)) + Data([50]) + SSHWire.text("test-user")
            + SSHWire.text("ssh-connection") + SSHWire.text("publickey-hostbound-v00@openssh.com")
            + Data([1]) + SSHWire.text("ssh-ed25519") + SSHWire.string(blob) + SSHWire.string(wrongHost)
        let mismatch = await agent.handle(Data([13]) + SSHWire.string(blob) + SSHWire.string(auth) + SSHWire.uint32(0), connectionID: connection)
        XCTAssertEqual(mismatch, Data([5]))
        // Removing the jump host changes scope even with the same destination.
        let direct = UUID()
        _ = await agent.handle(last, connectionID: direct)
        let changed = Task { await agent.handle(SSHTestKey.request(blob), connectionID: direct) }
        let changedApproval = try await pendingApproval(agent)
        XCTAssertTrue(changedApproval.forwardingHostFingerprints.isEmpty)
        agent.respond(to: changedApproval.id, allow: false)
        _ = await changed.value
        // Closing a connection cancels its approval and discards its binding.
        agent.connectionClosed(connection)
        let unbound = Task { await agent.handle(SSHTestKey.request(blob), connectionID: connection) }
        let unboundApproval = try await pendingApproval(agent)
        XCTAssertNil(unboundApproval.hostFingerprint)
        agent.respond(to: unboundApproval.id, allow: true, rememberUntilLock: true)
        _ = await unbound.value
        let stillUnbound = Task { await agent.handle(SSHTestKey.request(blob), connectionID: connection) }
        let stillApproval = try await pendingApproval(agent)
        agent.connectionClosed(connection)
        let closed = await stillUnbound.value
        XCTAssertEqual(closed, Data([5]))
        agent.respond(to: stillApproval.id, allow: true)
    }
}

extension SSHAgentLifecycleTests {
    func testGrantDoesNotCoverOtherUsernameAndDisableClearsIt() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let host = Curve25519.Signing.PrivateKey(), connection = UUID()
        let packet = try SSHBindingFixture.packet(key: host, session: Data(repeating: 1, count: 32))
        _ = await agent.handle(packet, connectionID: connection)
        let first = Task { await agent.handle(SSHTestKey.request(blob), connectionID: connection) }
        let request = try await pendingApproval(agent)
        agent.respond(to: request.id, allow: true, rememberUntilLock: true)
        _ = await first.value
        let auth = SSHWire.string(Data(repeating: 1, count: 32)) + Data([50]) + SSHWire.text("another-user")
            + SSHWire.text("ssh-connection") + SSHWire.text("publickey") + Data([1])
            + SSHWire.text("ssh-ed25519") + SSHWire.string(blob)
        let other = Task { await agent.handle(Data([13]) + SSHWire.string(blob) + SSHWire.string(auth) + SSHWire.uint32(0), connectionID: connection) }
        let otherApproval = try await pendingApproval(agent)
        XCTAssertEqual(otherApproval.username, "another-user")
        agent.respond(to: otherApproval.id, allow: false)
        let denied = await other.value
        XCTAssertEqual(denied, Data([5]))
        agent.setEnabled(false)
        agent.setEnabled(true)
        let fresh = UUID()
        _ = await agent.handle(packet, connectionID: fresh)
        let again = Task { await agent.handle(SSHTestKey.request(blob), connectionID: fresh) }
        let cleared = try await pendingApproval(agent)
        agent.respond(to: cleared.id, allow: true) // Allow once never creates a grant.
        _ = await again.value
        let onceMore = Task { await agent.handle(SSHTestKey.request(blob), connectionID: fresh) }
        let onceApproval = try await pendingApproval(agent)
        agent.respond(to: onceApproval.id, allow: false)
        _ = await onceMore.value
    }

    func testFailedBindingCannotFallBackToUnboundApproval() async throws {
        let (agent, blob, _) = try await setupAgent()
        defer { agent.setEnabled(false) }
        agent.setVaultUnlocked(true)
        let connection = UUID()
        var packet = try SSHBindingFixture.packet(key: Curve25519.Signing.PrivateKey(), session: Data(repeating: 1, count: 32))
        packet[packet.count - 2] ^= 1
        let binding = await agent.handle(packet, connectionID: connection)
        XCTAssertEqual(binding, Data([28]))
        let result = await agent.handle(SSHTestKey.request(blob), connectionID: connection)
        XCTAssertEqual(result, Data([5]))
        XCTAssertNil(agent.approval)
    }
}
