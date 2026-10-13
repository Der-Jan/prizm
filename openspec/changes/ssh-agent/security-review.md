# SSH agent security review

Review date: 2026-10-13. Scope: the local SSH agent implementation, key parsing
and signing, socket transport, approval UI, and vault lifecycle integration.
This is a focused source review with regression and integration tests, not an
independent security audit of the entire password manager.

## Findings fixed

1. **Slow clients could exhaust connection slots.** A timeout on each `recv`
   allowed a client sending occasional bytes to renew its waiting time. Four
   such clients could prevent normal SSH requests. Header and body now share a
   single monotonic deadline; writes also have an absolute deadline. The
   `testSlowFrameCannotExtendReadDeadline` regression failed before the fix and
   passes afterward. Limits remain four clients, 65,536 bytes per packet, and
   256 requests per connection.
2. **One malformed key could block all valid keys.** A parse failure during
   identity enumeration aborted the entire operation. Invalid or unsupported
   entries are now skipped individually, with a generic visible error and
   secret-free logging. Key strings are bounded before parsing; approval names
   are bounded by UTF-8 bytes. The
   `testCorruptVaultKeyDoesNotBlockValidKeys` regression failed before the fix
   and passes afterward.

This review predates the session-binding extension described in
session-binding.md; its validation is recorded separately in validation.md.
No approval bypass or private-key disclosure was identified in the reviewed
paths. Signing still requires an unlocked vault and approval for that request;
lock, disable, disconnect and timeout invalidate pending requests. The item is
re-read and its private/public key correspondence checked after approval.

## Verification

- Full AddressSanitizer suite: 513 passed, zero failed, three opt-in tests
  skipped (516 total).
- Separate signed sandbox integration: real `ssh-add` listing, independent
  OpenSSL signature verification and a successful OpenSSH login against a
  temporary loopback server. Uses a public test key in a mock vault.
- Signed universal Release build and strict code-signature verification pass.
- Test hosts use argument-domain settings to disable the production agent and
  a unique integration socket, leaving a running user's socket untouched.
- User confirmed the approval dialog appears above Terminal. Automated native
  UI journeys and VoiceOver verification remain incomplete. The full test run
  also reports main-thread/QoS runtime warnings; passing tests do not establish
  absence of responsiveness problems.

## Remaining security boundaries

- Same-user processes can request approval; neither client process identity nor
  destination hostname is authenticated. Approve requests you initiated.
  Destination constraints remain unsupported. The subsequent session-binding
  extension adds host-key proof and explicitly scoped grants until lock.
- Buffer clearing is best effort: Swift strings, copy-on-write buffers and
  framework key objects prevent a guarantee that every memory copy is erased.
- The local Release artifact is Apple Development signed and includes
  `com.apple.security.get-task-allow`. It is a local test build, not a hardened
  distribution-signing configuration. A public release should use an appropriate
  distribution identity and verify that debugger access is disabled.

These boundaries are not changed by raising the approval window. No notification
permission, additional production entitlement, helper or dependency was added.
