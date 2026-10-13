# Native SSH agent

Prizm provides an opt-in SSH agent at its sandbox home directory plus
`.bitwarden-ssh-agent.sock`: normally
`~/Library/Containers/de.b0x42.Prizm/Data/.bitwarden-ssh-agent.sock`.
The settings expose the resolved path. An existing path is never replaced or
unlinked; only the app's own socket is removed on stop or exit. Socket mode is
0600 and peers must share its effective UID. No TCP listener, XPC helper,
root privileges, global daemon, additional entitlement, or key files.

The sandboxed app owns vault access, key parsing, signatures and a SwiftUI
approval for signing, with an explicit optional grant until vault lock for the
exact key/username/verified host-key forwarding path. See session-binding.md.
The signed probe confirms bind/listen inside
the container using the existing entitlements. The real-home Bitwarden path
failed with EPERM; the user explicitly selected the container path instead.

Key listing and signing require an unlocked vault. Lock, sleep, screen lock,
sign-out, disabling the agent and socket disconnection invalidate pending
requests. Late results cannot sign after a session change. Requests time out
within 45 seconds, and at most one approval is pending. Listing returns at most
64 nondeleted keys. Master-password-reprompt items are excluded until that
additional authentication can be implemented.

Initial formats: unencrypted OpenSSH Ed25519 and PEM RSA (PKCS#1/PKCS#8), with
Ed25519 or RSA SHA-256/SHA-512 signing via CryptoKit/Security.framework. Encrypted
keys, OpenSSH RSA private containers, ECDSA, security keys and SSH certificates
are explicitly unsupported. No extra cryptographic dependencies or custom
cryptographic algorithms are introduced.

Identity-list, verified OpenSSH session binding and SSH public-key-authentication
signing are allowed, including OpenSSH hostbound payloads whose host key must
match the verified binding when present. Other
operations (including ssh-add mutation, constrained imports and arbitrary data
or Git commit signing) fail. The UI identifies key/fingerprint and parsed SSH
username and verified session host-key fingerprint when available; it never
claims a verified destination hostname or application identity.

Protocol parsing has bounded frames (64 KiB), handles partial/coalesced input,
rejects truncation/trailing bytes/invalid flags, and serializes requests per
connection. At most four connections are accepted. No secrets or raw signature
payloads appear in logs. README documents SSH_AUTH_SOCK, shell persistence,
ssh-add -L and socket conflicts; SECURITY and ACCESSIBILITY describe the agent
and approval interaction. Acceptance includes real OpenSSH signature verification,
request refusal on lock/denial/timeout and signed sandbox-to-socket use.
