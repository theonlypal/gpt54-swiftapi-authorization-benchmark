# GPT-5.4 x SwiftAPI authorization benchmark

Sharthok Rayan Pal — SwiftAPI Labs

80 direct GPT-5.4 Responses API generations across four local domains, paired
authorization conditions, and adversarial enforcement. The model proposes;
the trusted SwiftAPI gate independently authorizes protected local operations.

## Protocol and verification

PREREGISTRATION.md, PROTOCOL.json, SCHEDULE.json, THREAT_MODEL.md and
MODEL_PROVENANCE.md define the study. FREEZE_COMMIT.txt and FREEZE_SHA256SUMS
identify its pre-inference instrument. The preserved core is under vendor/.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python verify_study.py
shasum -a 256 -c SHA256SUMS
```

Offline verification needs no API/signing key or network after dependencies.
Recorded evidence replay is cross-platform. Live client execution tests require
macOS sandbox-exec; there is no unsandboxed fallback. pytest fixtures are
development checks, not model inference.

## Layout and deliberate live execution

- raw/: exact requests/responses, safe headers, metadata and usage.
- execution/: proposals, grants, client isolation, events and state readbacks.
- results/: generated counts and complete outcomes.
- verification/: test and offline replay reports.
- output/pdf/: paper.

run_gpt54.py preflight and primary perform paid API calls only with an explicit
OPENAI_API_KEY environment variable. enforce_gpt54.py runs saved proposals
through the real local gateway. Existing receipt paths cannot be overwritten.
These commands are not needed for offline verification. A new replication must
use fresh outputs and an explicit budget, not alter sealed evidence.

Capability does not license consequence. Prompting alone is not authorization.
