# Changelog

## 0.4.0 — 2026-04-09

### Added

- **`Connection#write_messages`** — batched multipart send for work-stealing
  send pumps. Dequeue a batch at once and write it under a single mutex
  acquisition instead of one lock per message. Amortizes lock overhead on
  high-throughput paths.

### Changed

- **Zero-alloc frame headers on the unencrypted hot send path.**
  `#write_frames` used to allocate, per part, a `Codec::Frame` object, a
  `.b` body copy, a 1-or-9-byte header String, and a concatenated wire
  String (a copy of the entire body just to glue the header on). The body
  copy was the dominant allocation — every 64 KB send produced a 64 KB
  throwaway String, feeding the GC at ~1.2 GB/s under sustained load.
  Headers are now packed into a reusable `@header_buf` via
  `Array#pack(buffer:)`, header and body are written separately
  (io-stream buffers them into one syscall per batch), the `Frame`
  object is gone, and the body is no longer copied. `@mechanism.encrypted?`
  is hoisted out of the per-frame loop. The encrypted path is unchanged —
  CURVE/BLAKE3ZMQ still authenticate over the full encoded frame and need
  a single wire String per part.

  Bench impact downstream in omq (push_pull + router_dealer, 1 and 3 peers,
  all transports): 48 improvements, 0 regressions across 72 measurements.
  Peaks: `router_dealer tcp 3p 64B +40.7%`, `push_pull ipc 1p 64 KB +28.8%`
  (crosses 1.3 GB/s).

## 0.3.0 — 2026-04-07

- Replace `[Async {}].each(&:wait)` with `Barrier` in tests.
- YARD documentation on all public methods and classes.
- Code style: two blank lines between methods and constants.
- Fix `#read_frame` decryption for non-CURVE encrypted mechanisms
  (e.g. BLAKE3ZMQ). Previously only CURVE's `\x07MESSAGE`-wrapped command
  frames were decrypted; inline-encrypted command frames (SUBSCRIBE, PING,
  etc.) were silently dropped, breaking PUB/SUB over BLAKE3ZMQ.

- **Breaking:** `Mechanism::Curve` API is now kwargs-only:
  `Curve.server(public_key:, secret_key:, crypto:)` and
  `Curve.client(server_key:, crypto:)`. Client keys are optional — when
  omitted, an ephemeral permanent keypair is auto-generated. INITIATE
  always contains `C + vouch + metadata` per RFC 26.
- **Breaking:** Authenticator now receives a `Protocol::ZMTP::PeerInfo`
  (with a `crypto::PublicKey`) via `#call`. The `#include?` duck-typing
  is removed. Sends an ERROR command to the client on rejection.
- Add `Protocol::ZMTP::PeerInfo` shared across mechanisms.
- Add `#maintenance` to `Mechanism::Curve` for automatic cookie key rotation.
  Returns `{ interval: 60, task: <Proc> }` on server-side mechanisms so the
  host application can rotate the cookie key every 60 seconds, limiting the
  forward secrecy exposure window.

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
