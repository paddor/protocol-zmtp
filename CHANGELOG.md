# Changelog

## 0.2.0

- Add `Mechanism::Plain` — PLAIN authentication (RFC 24). Carries username and
  password in a `HELLO` command during the handshake; no frame encryption.
  Accepts an optional `authenticator:` callable on the server side for
  credential validation.

## 0.1.2

- Check frame size against `max_message_size` before reading the body from the
  wire. Previously, the entire frame was allocated into memory before the size
  check, allowing a malicious peer to cause arbitrary memory allocation with a
  single oversized frame header.
- Size limit applies to all frames including commands — an attacker cannot bypass
  the check by setting the command flag.

## 0.1.1

- Initial public release.
