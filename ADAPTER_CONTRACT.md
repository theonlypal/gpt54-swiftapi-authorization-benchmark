# SwiftAPI protected execution adapter contract

The financial test backend is a local integer-unit ledger. It is connected to the
same SwiftAPI action envelope, binding condition, Ed25519 signature verification,
execution-time policy check, revocation check and nonce-consumption path as the
other protected capabilities. There is no simulated signature verifier or
model-supplied approval oracle. The original SwiftAPI authorization core is
preserved byte-for-byte under `vendor/`.

## Trust and interface

Only trusted broker code may invoke `TransactionalAdapter.apply(transaction,
action, verified)`. `VerifiedExecution` is an internal data type, not an
authentication mechanism: a caller who can execute arbitrary code in the broker
process can construct it. The security boundary is the independently protected
broker process, signing authority and state store, not Python type checking.
The agent HTTP surface exposes execution only and never exposes signing,
approval, policy mutation, adapter replacement or raw storage access.

The signed authorization binds the exact action hash (including actor,
capability, parameters and intent), condition hash, current policy-state hash,
nonce, issuer, issue time and expiry. The gate verifies it again before the
protected call. The adapter may neither infer approval from language nor
rewrite a target or amount. Revocation prevents a grant that has not crossed
the serialized execution boundary; it cannot undo an already committed effect.

## Local financial semantics

`sim.transfer` permits only the configured treasury-to-vendor transfer within
one actor namespace, using positive bounded integer units. The field `cents`
denotes hundredths of a simulated unit, not a claim about any real currency.
Balances, the one-use claim, the effect row and the signed receipt commit in one
SQLite transaction. Insufficient balance, invalid authorization or rollback
leaves all balances unchanged. Concurrency is serialized with `BEGIN IMMEDIATE`.

The verifier reconstructs balances from raw authorized actions and compares them
with a separately read final database snapshot. A signature alone does not prove
that the transfer happened. The verification claim assumes the trusted host and
operator did not fabricate or suppress the entire record; signatures do not
provide independent observation of a hostile host.

## Connecting an external financial service

The authorization envelope and verification protocol need not change. A new
adapter and deployment must, however, be qualified before it is enabled:

1. Register a new, explicitly scoped capability and bind the exact amount,
   currency, source, beneficiary, fee limit and operation type in its parameters.
   Resolve identifiers from trusted configuration. Retain the same signed
   action/condition/state/nonce protocol. Re-freeze the enlarged capability set.
2. Keep provider credentials and approval authority in a separate protected
   service/account or workload identity. Never give them to the model client.
3. Atomically consume the grant and create a durable outbox command. Commit
   before any network dispatch. Do not put an external transfer inside a local
   transaction and assume rollback can undo it.
4. Use a stable, exact-parameter-bound idempotency identifier at the destination.
   Keep the local consumed-command record beyond the destination's deduplication
   window. Neither an HTTP retry nor a new identifier may silently create a
   second transfer. The provider's actual semantics must be tested.
5. Distinguish AUTHORIZED/QUEUED, DISPATCHED, CONFIRMED, REJECTED and UNKNOWN.
   A timeout is UNKNOWN, not proof of zero consequence. Reconcile using provider
   object IDs, authenticated readback and verified event notifications before
   reporting completion. Do not treat a signed local receipt as settlement.
6. Define the revocation cutoff and recovery behavior, protect secrets and
   network egress, and qualify crashes, duplicated deliveries, stale policies,
   concurrent dispatch, amount precision and reconciliation in the provider's
   sandbox. Account eligibility, regulatory obligations and production approval
   remain outside this experiment. No external adapter is enabled here.

## Documentation basis

- [OWASP Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html):
  server-side authorization, transaction-data integrity, unique limited-lived
  credentials and a final authorization check before execution.
- [Stripe testing](https://docs.stripe.com/testing): sandbox transactions do not
  move funds; test credentials and test data are distinct from live use.
- [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests):
  destination retry and parameter-matching semantics matter; API v1 keys can be
  pruned after their retention period. Idempotency is not authorization.
- [AWS transactional outbox](https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html):
  local state and external delivery are a dual-write problem; duplicate delivery
  still requires idempotent consumption.

Consulted November 8, 2026. These sources inform the contract; they do not certify
SwiftAPI. No Stripe, banking, brokerage or payment-network API is called.
