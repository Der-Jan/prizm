import Foundation
import Darwin
import os.log

/// Container-local, same-UID Unix transport. It never imports or stores keys.
/// Blocking socket IO runs on bounded utility workers, outside the main actor.
/// Frame size, clients and request deadlines bound untrusted local input.
nonisolated final class SSHAgentSocket: @unchecked Sendable {
    typealias Handler = @Sendable (Data, UUID) async -> Data
    private let lock = NSLock()
    private let logger = Logger(subsystem: "com.prizm", category: "SSHAgentSocket")
    private var listener: DispatchSourceRead?
    private var clients: Set<Int32> = []
    private var active = false
    private var ownedSocket: (dev_t, ino_t)?
    let path: String
    private let handler: Handler
    private let onDisconnect: @Sendable (UUID) async -> Void
    private let ioTimeout: TimeInterval

    init(path: String, ioTimeout: TimeInterval = 45, onDisconnect: @escaping @Sendable (UUID) async -> Void = { _ in }, handler: @escaping Handler) {
        self.path = path
        precondition(ioTimeout > 0 && ioTimeout.isFinite)
        self.ioTimeout = ioTimeout
        self.handler = handler
        self.onDisconnect = onDisconnect
    }

    func start() throws {
        guard path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path), !path.utf8.contains(0) else {
            throw Self.error("SSH socket path is too long.")
        }
        var existing = stat()
        guard lstat(path, &existing) != 0, errno == ENOENT else {
            throw Self.error("The SSH socket path already exists. Stop the other agent or remove its stale socket before enabling Prizm.")
        }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Self.error("Could not create the SSH socket.") }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            path.utf8CString.withUnsafeBytes { buffer.copyBytes(from: $0) }
        }
        // umask is process-global; chmod follows bind before listen, so there is
        // no accepting window with permissive access. Peers are also UID checked.
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else { close(fd); throw Self.error("Could not bind the SSH socket: \(String(cString: strerror(errno)))") }
        var entry = stat()
        guard lstat(path, &entry) == 0 else { close(fd); throw Self.error("Could not inspect the SSH socket.") }
        ownedSocket = (entry.st_dev, entry.st_ino)
        guard chmod(path, 0o600) == 0, listen(fd, 4) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
            close(fd); removeOwnedSocket(); throw Self.error("Could not secure or listen on the SSH socket.")
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue(label: "com.prizm.ssh.accept", qos: .utility))
        lock.withLock { active = true; listener = source }
        source.setEventHandler { [weak self] in self?.acceptClients(fd) }
        source.setCancelHandler { close(fd) }
        source.resume()
        logger.info("SSH socket started")
    }

    func stop() {
        let source = lock.withLock { () -> DispatchSourceRead? in
            active = false
            for fd in clients { shutdown(fd, SHUT_RDWR) }
            let result = listener
            listener = nil
            return result
        }
        source?.cancel()
        removeOwnedSocket()
        logger.info("SSH socket stopped")
    }

    private func removeOwnedSocket() {
        guard let ownedSocket else { return }
        var entry = stat()
        if lstat(path, &entry) == 0, entry.st_dev == ownedSocket.0, entry.st_ino == ownedSocket.1 {
            if unlink(path) != 0 { logger.error("Could not remove owned SSH socket") }
        }
        self.ownedSocket = nil
    }

    private func acceptClients(_ fd: Int32) {
        while true {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            var uid: uid_t = 0, gid: gid_t = 0
            guard getpeereid(client, &uid, &gid) == 0, uid == geteuid() else {
                logger.error("Rejected SSH socket peer")
                close(client)
                continue
            }
            let admitted = lock.withLock { () -> Bool in
                guard active, clients.count < 4 else { return false }
                clients.insert(client)
                return true
            }
            guard admitted else { close(client); continue }
            // Darwin can inherit O_NONBLOCK from the listening descriptor.
            // Each admitted worker uses bounded blocking IO, so clear that flag.
            let flags = fcntl(client, F_GETFL)
            guard flags >= 0, fcntl(client, F_SETFL, flags & ~O_NONBLOCK) == 0 else {
                lock.withLock { clients.remove(client) }
                close(client)
                continue
            }
            _ = fcntl(client, F_SETFD, FD_CLOEXEC)
            var noSignal: Int32 = 1
            guard setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                lock.withLock { clients.remove(client) }
                close(client)
                continue
            }
            DispatchQueue.global(qos: .utility).async { [self] in serve(client) }
        }
    }

    private func serve(_ fd: Int32) {
        let connectionID = UUID()
        defer {
            lock.withLock { clients.remove(fd); close(fd) }
            Task { [onDisconnect] in await onDisconnect(connectionID) }
        }
        var requests = 0
        while requests < 256, lock.withLock({ active }) {
            // One absolute budget covers both header and body. Per-recv socket
            // timeouts alone let a trickling client renew the budget indefinitely.
            let deadline = ContinuousClock.now + .seconds(ioTimeout)
            guard let header = read(fd, count: 4, deadline: deadline) else { return }
            requests += 1
            let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard length > 0, length <= SSHWire.maximumPacket,
                  var packet = read(fd, count: Int(length), deadline: deadline) else { return }
            defer { packet.resetBytes(in: packet.indices) }
            // Reject mutation requests here, before private-key import payloads
            // could reach the application. Only list and sign are supported.
            guard packet.first == 11 || packet.first == 13 || packet.first == 27 else {
                guard write(fd, bytes: SSHWire.string(Data([5]))) else { return }
                continue
            }
            let result = SSHSocketReply()
            let task = Task { [handler, packet] in
                let reply = await handler(packet, connectionID)
                result.finish(reply)
            }
            // A client closing its socket cancels the app's pending approval.
            let disconnect = Task.detached {
                while !Task.isCancelled {
                    var byte: UInt8 = 0
                    let count = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
                    if count == 0 || (count < 0 && errno != EAGAIN && errno != EINTR) {
                        task.cancel()
                        return
                    }
                    do { try await Task.sleep(for: .milliseconds(100)) }
                    catch { return } // Cancelled when this request completes.
                }
            }
            let completed = result.ready.wait(timeout: .now() + 46)
            disconnect.cancel()
            guard completed == .success else { task.cancel(); return }
            guard lock.withLock({ active }), let reply = result.value,
                  reply.count <= SSHWire.maximumPacket, write(fd, bytes: SSHWire.string(reply)) else { task.cancel(); return }
        }
    }

    private func read(_ fd: Int32, count: Int, deadline: ContinuousClock.Instant) -> Data? {
        var bytes = Data(count: count)
        var completed = false
        defer { if !completed { bytes.resetBytes(in: bytes.indices) } }
        var offset = 0
        while offset < count {
            guard wait(fd, for: Int16(POLLIN), until: deadline) else { return nil }
            let result = bytes.withUnsafeMutableBytes { raw in
                recv(fd, raw.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT)
            }
            if result < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard result > 0 else { return nil }
            offset += result
        }
        completed = true
        return bytes
    }

    private func write(_ fd: Int32, bytes: Data) -> Bool {
        var offset = 0
        let deadline = ContinuousClock.now + .seconds(ioTimeout)
        while offset < bytes.count {
            guard wait(fd, for: Int16(POLLOUT), until: deadline) else { return false }
            let result = bytes.withUnsafeBytes { raw in
                send(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset, MSG_DONTWAIT)
            }
            if result < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard result > 0 else { return false }
            offset += result
        }
        return true
    }

    private func wait(_ fd: Int32, for event: Int16, until deadline: ContinuousClock.Instant) -> Bool {
        while true {
            let remaining = ContinuousClock.now.duration(to: deadline)
            guard remaining > .zero else { return false }
            let parts = remaining.components
            let milliseconds = parts.seconds * 1000 + parts.attoseconds / 1_000_000_000_000_000 + 1
            var descriptor = pollfd(fd: fd, events: event, revents: 0)
            let result = poll(&descriptor, 1, Int32(clamping: milliseconds))
            if result < 0 && errno == EINTR { continue }
            return result > 0 && ContinuousClock.now < deadline
                && descriptor.revents & (event | Int16(POLLHUP)) != 0
        }
    }

    private static func error(_ message: String) -> NSError {
        NSError(domain: "PrizmSSHAgent", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

nonisolated private final class SSHSocketReply: @unchecked Sendable {
    let ready = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var bytes: Data?
    var value: Data? { lock.withLock { bytes } }
    func finish(_ bytes: Data) { lock.withLock { self.bytes = bytes }; ready.signal() }
}
