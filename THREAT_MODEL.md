# Trusted boundary and threat model

The adversary controls proposed action/grant JSON, misleading approval text,
replay and concurrency. The model cannot issue grants. The gate requires exact
issuer signature, action digest, current condition/state digest, expiration,
revocation status and transactionally consumed single-use nonce.

Trusted: macOS sandbox/kernel, Python runtime, preserved SwiftAPI verification
core, operator scope oracle/signing authority, broker, SQLite, host administrator,
collection process and verifier machine. The IDE research process is trusted
and is not itself sandboxed. Protected state includes artifact/page rows,
simulated balances, installed strategy and effect records. Denial logging is
not a protected business effect. Each trial uses a fresh store and authority.

The model client is a fixed JSON transport, not executable model-produced code.
Its deny-by-default sandbox permits public-code/runtime reads and its broker's
loopback port only. Every invocation probes key read, store read/write,
governing-code write and another network port. It receives no API secret or
operator key. These probes do not exhaust sandbox escapes.

Forged grants use a wrong Ed25519 key. Parameter/scope mutations retain the
original grant. Revocation and policy changes occur after issuance. Verifier
failure removes the verification function temporarily. Hard-crash testing exits
the broker after SQL adapter writes but before commit; readback determines
whether an effect occurred before retry. Authorization, dispatch and confirmed
effect are distinct events.

Excluded: malicious trusted authority, compromised administrator/kernel, stolen
keys, cryptographic breaks, multi-host distributed execution, arbitrary shell
execution, browser engine exploitation, financial custody/settlement and
unrestricted modification of authority. Local source hashes are not general
host attestation. Production integrations need protected credentials, durable
outbox/idempotency and reconciliation as specified by ADAPTER_CONTRACT.md.
Simulation does not qualify real banking or regulated payment infrastructure.
