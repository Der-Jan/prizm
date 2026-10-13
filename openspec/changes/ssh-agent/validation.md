# Validation

- Signed minimal probes on macOS 26.6.2: real-home bind fails with EPERM even
  with an exact file exception; container bind/listen succeeds with Prizm's
  existing sandbox entitlements. User selected container path, no helper.
- Wire acceptance regression observed failing before implementation; hostbound
  regression observed failing before adding the actual OpenSSH request format.
  Additional key, transport and lifecycle tests were added during implementation.
- Full AddressSanitizer suite passes; opt-in signed/socket and mTLS persistence
  tests skip in unsigned runs. Dedicated signed socket test passes separately.
- Ed25519 public key and verification checked against RFC 8032 vectors. Generated
  CryptoKit signatures are randomized, so byte equality against deterministic
  reference signatures is not expected. RSA SHA-256/SHA-512 verification passes
  with Security.framework; unsupported flags and malformed imports are rejected.
- `python3 tests/ssh/integration.py` passes with a signed sandboxed test host,
  real ssh-add key listing, fragmented framing, independent OpenSSL verification
  and an actual OpenSSH login against a temporary loopback sshd. Uses a published
  RFC test key in a mock vault and an opt-in test-only automatic approver.
- Existing files and symlinks are preserved; socket mode and cleanup tested.
  Pending requests fail on denial, timeout, task cancellation, client disconnect,
  lock and disabling. Deleted/re-prompt keys are excluded. Root lock disables
  signing synchronously before async cache clearing. ViewModel presentation tested.
- Universal signed Release builds successfully; strict codesign verification
  succeeds. No new packages or production entitlements.

Manual native-window/VoiceOver and full sleep/wake acceptance remain. There is
no automated XCUITest for the new approval window yet. No upstream PR or merge
is claimed; changes remain on the local SSH feature branch for review.

Foreground fix: the approval window now restores/orders itself after its native
NSWindow attaches, then requests app activation. Window-order regression observed
failing before implementation. Nine activation and SSH lifecycle tests pass (the
opt-in signed socket test skips in this targeted unsigned run). Tests cover
cancelled/detached windows and one activation per request. Desktop focus should
be confirmed manually on the user's machine.

User desktop testing showed activation alone still left the dialog behind Terminal.
The pending approval now uses floating window priority and stays visible while
Prizm is inactive. Its previous level, Space behavior and hide-on-deactivate flag
are restored when the request ends or the view detaches. The new priority
regression failed before the change; cancellation/closing restoration are tested.
No macOS notification permission is requested or required for this window behavior.

The user subsequently confirmed the foreground behavior works. A focused
[security review](security-review.md) fixed two availability regressions and
verified the final source with 513 passing AddressSanitizer tests, a separate
signed OpenSSH integration test, and a signed Release build.

## Session binding and remembered approvals

The session-bind acceptance/rebind and mismatched signing-session regressions
failed before implementation. The remembered-approval regression also failed
before implementation. The final full AddressSanitizer run passed 520 tests,
with three opt-in tests skipped (523 total). Additional SSH coverage checks
tampering, trailing bytes, RSA SHA-256/SHA-512 and all three NIST ECDSA curves,
forwarded paths, hostbound-key mismatch, username scope, unbound requests,
Allow Once, disconnect, lock and disable. Unsupported extensions do not poison
a connection; a failed session binding does prevent signing on that connection.

The signed external integration passed independent OpenSSL verification and two
real OpenSSH logins using distinct connections to a temporary loopback server.
The first bound login explicitly grants approval until lock; the second verifies
a new binding and reuses the grant without prompting. The test asserts exactly
one bound approval (plus a separate unbound synthetic request). The public RFC
test key and mock vault remain isolated from the user's normal socket/vault.

An initial full regression started before the external TLS fixture directory
was ready, so its three mTLS integration tests failed. After preparing the fixture,
the full suite passed; this was test setup rather than an SSH code failure.
The final error-display/crypto-service-boundary changes are additionally checked
with the targeted SSH and native window activation suite.

No hostname verification, persistent trust, `ssh-add -h` constraints or automatic
approval for unbound clients is claimed. The new button and host/path display
remain subject to user desktop/VoiceOver acceptance; existing foreground window
behavior is unchanged.

User acceptance: the user tested multiple configurations, including multiple
agent-forwarding hops, and confirmed robust behavior before authorizing commit
and push. VoiceOver and automated XCUITest coverage remain separate gaps.
