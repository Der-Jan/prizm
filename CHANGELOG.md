# Changelog

## Unreleased

- Fix a crash when locking the vault (including sleep and screen lock) by using
  the actual index ranges when zeroing sliced organization and vault key buffers.
- Add an optional sandboxed SSH agent for OpenSSH Ed25519 and PEM RSA keys,
  with per-use approval, verified OpenSSH session binding and optional approvals
  remembered until vault lock; shell setup is documented in README.
