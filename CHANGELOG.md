# Changelog

## [0.2.3a4](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.3a4) (2026-07-21)

- Serialize the short password-strength validator because its temporary cache
  lock is not thread-safe, while preserving concurrent PBKDF key derivation.

## [0.2.3a3](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.3a3) (2026-07-21)

- Keep password-strength validation and password-key derivation off the
  Tornado event loop.
- Preserve isolated per-connection password-handshake state while retaining
  strength validation for every connection.

## [0.2.3a2](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.3a2) (2026-07-16)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.2.3a1...0.2.3a2)

**Merged pull requests:**

- fix: consume websocket writes after peer close [\#9](https://github.com/thalovant/hivemind-websocket-protocol/pull/9) ([goldyfruit](https://github.com/goldyfruit))

## [0.2.3a1](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.3a1) (2026-07-16)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.2.2a1...0.2.3a1)

**Merged pull requests:**

- fix: cache listener handshake private key [\#8](https://github.com/thalovant/hivemind-websocket-protocol/pull/8) ([goldyfruit](https://github.com/goldyfruit))

## [0.2.2a1](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.2a1) (2026-07-16)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.2.1a7...0.2.2a1)

**Merged pull requests:**

- fix: repair reusable CI permissions [\#7](https://github.com/thalovant/hivemind-websocket-protocol/pull/7) ([goldyfruit](https://github.com/goldyfruit))

## [0.2.1a7](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.1a7) (2026-07-16)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.2.1a6...0.2.1a7)

**Merged pull requests:**

- Constrain alpha release to source artifacts [\#6](https://github.com/thalovant/hivemind-websocket-protocol/pull/6) ([goldyfruit](https://github.com/goldyfruit))

## [0.2.1a6](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.1a6) (2026-07-16)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.2.1a5...0.2.1a6)

**Merged pull requests:**

- Skip remote database repair during WSS auth [\#5](https://github.com/thalovant/hivemind-websocket-protocol/pull/5) ([goldyfruit](https://github.com/goldyfruit))

## [0.2.1a5](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.1a5) (2026-07-13)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.2.1a3...0.2.1a5)

**Merged pull requests:**

- Harden organization security controls [\#4](https://github.com/thalovant/hivemind-websocket-protocol/pull/4) ([goldyfruit](https://github.com/goldyfruit))

## [0.2.1a3](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.1a3) (2026-06-08)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.2.1a2...0.2.1a3)

## [0.2.1a2](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.2.1a2) (2026-06-08)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.0.4a1...0.2.1a2)

**Merged pull requests:**

- Add websocket heartbeat settings [\#3](https://github.com/thalovant/hivemind-websocket-protocol/pull/3) ([goldyfruit](https://github.com/goldyfruit))
- Trust client IP from known proxies [\#2](https://github.com/thalovant/hivemind-websocket-protocol/pull/2) ([goldyfruit](https://github.com/goldyfruit))
- Handle bad websocket auth [\#1](https://github.com/thalovant/hivemind-websocket-protocol/pull/1) ([goldyfruit](https://github.com/goldyfruit))

## [0.0.4a1](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.0.4a1) (2025-12-18)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.0.3...0.0.4a1)

## [0.0.3](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.0.3) (2025-04-26)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.0.3a1...0.0.3)

## [0.0.3a1](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.0.3a1) (2025-04-26)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.0.2...0.0.3a1)

## [0.0.2](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.0.2) (2024-12-29)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.0.2a1...0.0.2)

## [0.0.2a1](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.0.2a1) (2024-12-29)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/0.0.1...0.0.2a1)

## [0.0.1](https://github.com/thalovant/hivemind-websocket-protocol/tree/0.0.1) (2024-12-28)

[Full Changelog](https://github.com/thalovant/hivemind-websocket-protocol/compare/3c7f5766be3b0e1efdba71ef6b966a40b21d5595...0.0.1)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
