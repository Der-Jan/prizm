# Implementation plan

1. Write wire/key/lifecycle regression tests and observe failures.
2. Implement bounded SSH wire decoding and Apple-framework signing.
3. Implement container-local Unix transport with same-UID peers.
4. Add Domain manager, settings and native approval dialog; integrate lock lifecycle.
5. Verify real OpenSSH interoperability, signed sandbox transport, tests and Release.

Complexity: a bounded Unix transport is required by the OpenSSH agent protocol.
The container socket works with the existing App Sandbox entitlements. The user's
preference excludes a separate helper or sandbox exceptions for a real-home path.

Approval-window activation uses a small NSViewRepresentable bridge: SwiftUI
openWindow is asynchronous and does not expose NSWindow ordering/focus. Once the
window attaches, a main-run-loop callback restores and raises that specific
window before requesting application activation. Stale/cancelled requests never
activate the window; no deprecated activation API. Only the pending approval temporarily uses floating window priority, remains visible when the app is inactive, and moves to the active Space. Original level/Space behavior/hide settings are restored on completion or detachment.
