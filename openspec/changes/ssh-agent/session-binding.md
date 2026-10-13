# Session binding and approvals until lock

Implement OpenSSH `session-bind@openssh.com` in the container-local agent. Verify
the host's signature over the supplied session identifier with Apple frameworks;
store a bounded forwarding chain per socket connection, never just a caller's
fingerprint claim. Reject malformed, invalid and inconsistent bindings. Match
subsequent authentication requests to the final verified session and, for
hostbound authentication, the final host key. An authentication binding closes
the chain; it cannot later be rebound. Disconnect clears connection state.

The additional explicit approval action is **Allow until vault locks**. Cache
grants in memory only, scoped to the exact vault public key, SSH username and
verified host-key forwarding path. Every new connection must independently
verify its own binding; cache entries do not replace cryptographic checks.
Unbound clients retain one-use approval and cannot obtain a remembered grant.
Allow Once and Deny do not create grants. Lock/sign-out/disable/shutdown clear
both grants and bindings. Keys are still re-read and validated before every
signature, including remembered approvals.

No hostname trust or known_hosts access is implied: session binding establishes
proof with a host key, not trust in its human-readable name. Display a host
fingerprint and forwarding path; state that hostname validation remains the
SSH client's responsibility. No persistent key, settings or entitlement changes.

Use bounded wire parsing and CryptoKit/Security.framework signature verification
for Ed25519, RSA SHA-2 and NIST ECDSA host keys. Certificates and security-key
host formats are unsupported. Forwarding grants are tied to the entire path.
Limits: four concurrent connections, 16 binds per connection, 128 cached grants.
Tests must cover signature tampering, session/host mismatch, rebind rules,
connection isolation, cache scope and clearing, and real OpenSSH interoperability.
