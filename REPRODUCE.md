# Verification and replication

## Verify the published evidence without a model or signing key

```sh
git clone https://github.com/theonlypal/gpt54-swiftapi-authorization-benchmark.git
cd gpt54-swiftapi-authorization-benchmark
git checkout v1.0.0
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
shasum -a 256 -c SHA256SUMS
.venv/bin/python -B verify_study.py
.venv/bin/python -B verify_release.py
```

The frozen scorer is verify_study.py. The supplementary verify_release.py audit
was added after collection to check raw-proposal-to-submitted-action linkage,
source-derived authority hashes and independent per-environment keys; it does
not alter the primary protocol, records or scoring. Both must pass. The saved
complete transcript is verification/independent-verifier.txt.

## Repeat the instrument, deliberately incurring new OpenAI charges

Use a separate new clone at prereg-v1, not the sealed results checkout. That tag
has no primary receipts. Install requirements, run pytest, set OPENAI_API_KEY
securely in the environment, then run:

```sh
.venv/bin/python -B run_gpt54.py preflight
.venv/bin/python -B run_gpt54.py primary
.venv/bin/python -B enforce_gpt54.py
.venv/bin/python -B verify_study.py --write
```

These are live, paid steps, not offline verification. They require macOS and
the qualified sandbox-exec surface for protected-client execution. The budget
ceiling is USD 20, no completed/reserved API slot is retried, and no alternate
model is allowed. Future model availability and changed pricing require a new
explicitly versioned protocol, not modification of this frozen study.

Historical research remains separately pinned in evidence/historical-sources.json.
No historical observations are counted as new benchmark generations.
