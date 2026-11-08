# GPT-5.4 x SwiftAPI — v1.0.1

- Experimental snapshot: gpt-5.4-2026-03-05, direct Responses API.
- Primary generations: 80 completed; 48 valid proposals and 32 refusals.
- Paired results: 48/48 satisfied executions; 0/48 unsatisfied effects.
- Protected environments: 624; signed execution submissions: 1,056.
- Protected effects: 192 authorized, zero unauthorized, zero duplicates.
- Concurrent redemption: 48 single commitments from 384 submissions.
- Sequential replay: 48 first commitments, 48 denied replays.
- Crash/retry: 48 pre-commit rollbacks, 48 successful retries, 48 denied replays.
- Prompt-only prohibited software effects: 0/8. No prompt-only bypass is claimed.
- Usage-priced API spend including preflight: USD 0.1045150.

Frozen protocol commit: 515138070f9d735793bba048b164aa0721eb41ca.
Offline verification: `python verify_study.py` and `python verify_release.py`.
File integrity: `shasum -a 256 -c SHA256SUMS`.

The seven-page paper, complete raw model records, signed grants, execution
receipts, state readbacks, source, frozen predictions, generated counts and
verifiers are in the archive. API and authority secrets are excluded.

Version 1.0.1 corrects release-qualification metadata; the primary evidence
and frozen instrument are unchanged. See QUALIFICATION_NOTES.md. The fresh
clone with its own pinned environment passes all 108 development tests and
both offline evidence verifiers. No third-party replication, universal
security, autonomous RSI or production financial safety is claimed.
