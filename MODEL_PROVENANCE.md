# Experimental model provenance

The sole experimental LLM is **gpt-5.4-2026-03-05**, served directly by OpenAI
at `https://api.openai.com/v1/responses`. No local model, proxy, alternate
provider, or fallback model is used. OpenAI documents this snapshot at
<https://developers.openai.com/api/docs/models/gpt-5.4>.

Requests use `reasoning.effort=none`, `max_output_tokens=512`, `store=false`,
`stream=false`, and `service_tier=default`. Temperature, top-p, seed, tools,
structured-output enforcement, conversation history and previous response IDs
are omitted. Exact prompts and inputs are frozen in PROTOCOL.json and SCHEDULE.json.
Raw response bodies, safe headers, request/response IDs, returned model IDs,
timestamps, status, usage and errors are retained. The API secret is an
environment variable available only to the collection process, never the client.

## Development versus experimental inference

The original 86 development tests use scripted clients, not a language model.
The saved development isolation qualification also uses a scripted client.
None is counted as a primary GPT-5.4 generation. New offline fixtures exercise
request construction, independent parsing and actual sandbox/gate fault cases;
they too are not model inference. Saved JUnit files identify each test.

The research executor is Codex; inspected local runtime metadata identified
`gpt-6-astra`. That runtime label is not the experimental subject, an immutable
weight revision or an independent evaluator. Private conversation records and
account identifiers are excluded.

## Components and authority

GPT-5.4 supplies action JSON or refusal. An operator-controlled scope oracle
checks frozen actor, capability and parameters. The trusted SwiftAPI authority
signs scoped grants. Gate.execute verifies issuer, exact action, current
condition/version, expiration, revocation and single-use nonce before effects.
The macOS-sandboxed JSON client can reach only the loopback execution endpoint,
not signing keys or protected storage. Independent offline code reconstructs
signatures and state readbacks. Separate implementation is not independent
third-party replication.

The authorization core `vendor/swiftapi/brake/core.py` is byte-identical to
the existing runtime, SHA-256
`fc97753bed740956fdfb50f382a090de8d03d66bcce5208c96c7faabe6db3fa1`.
Runtime revision: `534a153cc469deced4152c06cb6ea1c984f994d3`.
SDK lineage: `d8925cdb11ffffe0f24b47087306f7025d97605b` (v1.3.1).
This is the actual signature verification path, not a mock.

No new GPT-5.4 observation is asserted by the preregistration. Executed counts
and exact returned identifiers are generated from preserved receipts after freeze.
