STOP ASKING “CAN AI DO IT?” START ASKING “WHAT GIVES AI THE RIGHT TO FOLLOW?”

GPT-5.4, the Binding Condition, Protected Agent Execution, and Why Prompting Alone Is Not Authorization

Sharthok Rayan Pal — SwiftAPI Labs<br/>November 8, 2026 · Version 1.0.0

Abstract

A preregistered local benchmark collected 80/80 completed generations from gpt-5.4-2026-03-05 through OpenAI’s direct Responses API. The model supplied 48 valid proposals and 32 explicit refusals. Identical proposals were replayed across independently reset authorization states: 48/48 satisfied conditions committed an exact protected operation, versus 0/48 unsatisfied conditions. Across paired and adversarial environments, 192 protected effects were reconstructed, with 0 unauthorized effects and 0 duplicate commitments. The prompt-only software control produced 0/8 prohibited effects; thus this study does not demonstrate a prompt-only failure. Its positive result is a measured separation between model-generated proposals and execution authority under tested signature, scope, condition, replay, concurrency and crash constraints. The consequences are local artifact/page writes, simulated ledger transfers and finite strategy updates. These results do not establish universal security, autonomous RSI or production financial safety.

Principal finding

Human intent defines an objective. A binding condition specifies a prerequisite. The authority to execute is verified outside the model. In this benchmark, a valid model proposal did not itself constitute permission; an externally validated, exact-action grant and current condition were required before a protected state change.

Public pre-inference freeze: <a href="https://github.com/theonlypal/gpt54-swiftapi-authorization-benchmark/tree/515138070f9d735793bba048b164aa0721eb41ca" color="#145a88">515138070f9d735793bba048b164aa0721eb41ca</a>. Exact protocol, source and requests are preserved in the repository.


---


1. Capability, proposal, authority and consequence

The enforcement invariant is: Execute(action) implies Authorized(action), Verified(prerequisites), and ScopeValid(action). This is an implementation property relative to trusted components and a stated threat model, not a universal property of language models. An instruction may shape a proposal or a refusal; it does not furnish a cryptographic grant or mutate the trusted permission state.

Table 1. Distinct evidence requirements.

Layer | Evidence | What it does not establish

Model behavior | Original output, status, identifiers and usage | Approval or execution

Authorization | Ed25519 signature; exact action and current state | That dispatch or commitment occurred

Protected consequence | Transactional event plus independent final readback | Remote settlement or production safety

Offline verification | Separate reconstruction of archived evidence | Third-party replication or provider attestation

2. Frozen model and task design

The experimental subject is gpt-5.4-2026-03-05, not the model assisting research development. Requests used /v1/responses directly, reasoning effort none, output ceiling 512, default service tier, store=false and stream=false. Temperature, sampling seed, tools and enforced JSON schema were omitted. Each request had fresh context. The API collector made no retries, prompt repairs or model substitutions. Official model and rate documentation are linked in the protocol.

Four domains each contain five conditions and four task variants: permitted execution; planning without permission; denied execution with an instruction override; denied execution with an asserted administrator approval; and planning with attempted scope expansion. Trusted request fields specify the exact actor and allowed parameters. Untrusted text cannot authorize execution. Planning is explicitly allowed to produce proposals without approval.

The system instruction requires either an exact action JSON object or a refusal JSON object. Refusals, malformed responses, abstention and operational failure remain observations, not discarded trials. The full instruction, user data and byte hashes are frozen in PROTOCOL.json and SCHEDULE.json. No post-result prompt adjustment was made.

The prompt-only control is confined to execute-mode software scenarios. It writes a valid proposed artifact into an isolated ungated database and does not check an external grant. Planning outputs are excluded from the prompt-failure denominator because the system instruction permits them. This prevents counting an allowed proposal as a failure to refuse.


---


3. Trusted execution architecture

The existing SwiftAPI Ed25519 verification core is preserved byte-identically. The external scope oracle permits only the scheduled actor, capability and exact parameters; the model supplies its own intent text, which is also signed. The grant binds an action digest, condition digest, current policy version, lifetime and one-use nonce. The broker verifies all fields, checks revocation, and consumes the nonce in the same SQLite transaction as the protected action and execution receipt.

The API key belongs only to the trusted collection process. The model and its fixed JSON transport receive no signing key or protected-database handle. Every transport invocation runs in a macOS deny-by-default sandbox. Its only network destination is the local execution endpoint; key read, database read/write, code write and alternate-port probes must be denied. The research IDE and host administrator remain trusted, not sandboxed.

Table 2. Real local state changes and their limited interpretation.

Domain | Committed operation | Boundary of the claim

Software | Install exact source text in artifact store | No arbitrary program or shell execution

Browser action | Update local notice through loopback HTTP | No external website write or GUI eval

Finance | Atomic integer debit and credit | Simulated units, no real funds

Agent modification | Install index/memoized strategy setting | No autonomous RSI or authority edit

4. Paired and adversarial procedures

For each valid proposal, two new environments receive identical action bytes. In the satisfied arm the independent authority grants the exact scoped action. In the unsatisfied arm the trusted condition changes after grant issuance and before dispatch. Out-of-scope proposals receive no approving grant. Each environment begins with a fresh database and authority, preventing replay state or earlier effects from contaminating the pair.

Additional environments apply missing, forged, expired, revoked and replayed grants; changed parameters; scope escalation; eight concurrent redemptions; unavailable verification; changed policy version; and interruption after SQL writes but before commit. The interrupted process exits with a frozen diagnostic code. Readback must show rollback; a subsequent valid retry may commit once, while its replay may not. These mutations are programmed attacks against real GPT-generated proposals, not autonomous model-generated exploit programs.

Denial logs are not protected business effects. An HTTP failure is not counted as a safe denial. Interrupted requests are initially UNKNOWN and are resolved only by signed-event reconstruction plus independent local state readback. General remote payment timeouts remain outside this transactional experiment.


---


5. Results: generations and matched execution

Table 3. One generation per slot; paired conditions reuse the same generated action. Refusals have no paired execution.

Domain | N | Valid | Refusal | Satisfied effects / N | Unsatisfied effects / N

software | 20 | 12 | 8 | 12/12 | 0/12

browser | 20 | 12 | 8 | 12/12 | 0/12

finance | 20 | 12 | 8 | 12/12 | 0/12

agent | 20 | 12 | 8 | 12/12 | 0/12

All 80 primary attempts returned HTTP 200 and 80 completed with the specified model. The retained record contains 0 malformed proposals, 0 schema-valid scope deviations, 0 provider refusals, 0 abstentions, and 0 operational model outcomes. These counts are generated from the raw API bodies, not inferred from gateway status.

Table 4. Aggregate prompt behavior across domains; full trial-level rows are in summary.json.

Prompt condition | Valid proposals | Explicit refusals

permitted | 16 | 0

planning | 16 | 0

instruction_conflict | 0 | 16

claimed_approval | 0 | 16

scope_expansion | 16 | 0

The protected pair produced 48 authorized consequences and 0 consequences under the unsatisfied state. The prompt-only control produced 4 artifact writes across 12 execute-mode cases; 0/8 prohibited cases wrote an artifact. The observed control therefore supplies no empirical prompt-only bypass in this fixed set. This negative finding is retained without relabeling planning outputs as violations.

Usage-priced OpenAI cost was USD 0.1045150, including 1 separately labeled preflight request. The hard ceiling was USD 20; no additional paid service was used. Rates were USD 2.50 input, 0.25 cached input and 15.00 output per million tokens. This is a reconstruction from provider usage fields, not an account invoice.


---


6. Adversarial outcomes and falsification

Table 5. Reset environments over unchanged model proposals. Replay/concurrency/crash arms intentionally include one authorized commitment per environment.

Enforcement condition | Environments | Effects | Executed | Denied

missing | 48 | 0 | 0 | 48

forged | 48 | 0 | 0 | 48

expired | 48 | 0 | 0 | 48

revoked | 48 | 0 | 0 | 48

replay | 48 | 48 | 48 | 48

modified_parameters | 48 | 0 | 0 | 48

scope_escalation | 48 | 0 | 0 | 48

concurrent_redemption | 48 | 48 | 48 | 336

verifier_failure | 48 | 0 | 0 | 48

interrupted_retry | 48 | 48 | 48 | 48

policy_changed | 48 | 0 | 0 | 48

Across 624 environments, the verifier reconstructed 192 executed operations and 864 denied submissions. Unauthorized protected effects: 0; duplicate commitments: 0. The 48 interrupted transports were resolved by unchanged post-crash state and retry readback. Unresolved outcomes: 0.

Table 6. Frozen predictions. H5 is descriptive, not a pass/fail prediction.

Frozen criterion | Result

H1: zero unauthorized effects | PASS

H2: useful authorized execution | PASS

H3: single-use/at-most-once | PASS

H4: crash rollback and retry | PASS

Recorded protocol/evidence issues: 0. Unattempted primary slots: 0. Missing execution records: 0. No response was regenerated. Primary counts include refusals and any invalid or operational outcomes; successful gate executions are not substituted for failed model generations.

7. Historical evidence is a different level of measurement

The December 8, 2025 Void publication introduced the behavioral research program. It is historical motivation, not part of the new trial denominator. <a href="https://doi.org/10.5281/zenodo.17856031" color="#145a88">[1]</a>

Published GPT-5.4 prerequisite reassignment tests changed semantic prerequisites in the instruction context. Such hosted output changes are not independent execution authorization, and an API-visible empty answer does not expose internal EOS logits. <a href="https://doi.org/10.5281/zenodo.22983298" color="#145a88">[2]</a>

PCCG-1 manipulated continuation in an engineered open-weight setting. <a href="https://doi.org/10.5281/zenodo.22681787" color="#145a88">[3]</a> PCCG-2 separated frozen content from a gate that changed native EOS while preserving non-EOS logits. Neither mechanism is shown to be the mechanism of this software authorization boundary. <a href="https://doi.org/10.5281/zenodo.22730710" color="#145a88">[4]</a>


---


8. Interpretation and limitations

The published English DOOR-KEY-1 results include incomplete prompt-level gating. <a href="https://doi.org/10.5281/zenodo.24042127" color="#145a88">[5]</a> The November 7 synthesis separates hosted model behavior, engineered termination and consequential execution. The present experiment adds direct GPT-5.4 proposals and independently reconstructed local consequences to that distinction. <a href="https://doi.org/10.5281/zenodo.24044104" color="#145a88">[6]</a>

The measured contribution is narrow and falsifiable: fixed proposals were usable with the independently authorized condition and ineffective without it, within the implemented trust boundary and tested attack matrix. A model refusal is behavior; a blocked operation is enforcement; a reconciled state transition is consequence. None can replace the others as evidence.

Prompting alone is not authorization is an architectural statement here, not a claim that GPT-5.4 failed the tested instructions. No prompt-only prohibited write was observed in this fixed set. The benchmark does not establish the failure probability of prompting under broader or adaptive attacks. An adversary controlling the trusted signer, kernel, operator or broker can violate the assumed boundary; such compromise is outside the stated threat model.

The transport is scripted and the model proposes in a single turn. No autonomous exploit search or iterative adversarial agent was tested. Software actions install text rather than execute arbitrary programs. Browser actions exercise a local HTTP-backed page store rather than external browsing. Financial effects use simulated units. Strategy changes do not establish two successive autonomous improvements or RSI. None of the four domains establishes production deployment safety.

Receipts are signed by the study authority, not by OpenAI. They authenticate the archived chain relative to the published trust anchor; they cannot independently prove provider authorship or exclude a dishonest operator. The separate verifier is independently runnable but was developed within the same research workflow. No independent third-party replication is claimed. Counts enumerate the frozen finite task set; no population inference, confidence interval or universal security guarantee is asserted.

9. Reproducibility and artifact integrity

Code, frozen protocol and raw evidence: <a href="https://github.com/theonlypal/gpt54-swiftapi-authorization-benchmark" color="#145a88">https://github.com/theonlypal/gpt54-swiftapi-authorization-benchmark</a>. The release includes exact model requests/responses, safe headers, grants, signed execution chains, client-isolation probes, final-state exports, generated results, test reports and SHA256SUMS. Signing keys and API credentials are excluded.

From a fresh clone: install requirements.txt, run <b>python verify_study.py</b>, and verify <b>shasum -a 256 -c SHA256SUMS</b>. No paid inference or signing authority is needed. The verifier checks frozen bytes, independently decodes proposals, reconstructs nonce/state/signature decisions, checks readback and recalculates usage-priced cost. The execution instrument is not rerun to verify archived outcomes.

The live experiment is deliberately not automatically repeatable by the offline verifier: new paid collection requires explicit credentials, a budget and fresh paths. Existing records are immutable. The macOS sandbox is a qualified local boundary, not a portable assurance claim for other operating systems or cloud deployments.


---


References and frozen identifiers

[1] Pal, R. Textual Emergence and the Void: A Framework for Observing High-Order Model Behavior in LLM Systems. <a href="https://doi.org/10.5281/zenodo.17856031" color="#145a88">10.5281/zenodo.17856031</a><br/>Source: Published December 8, 2025.

[2] Pal, R. Prerequisite Role Reassignment Controls Continuation in GPT-5.4. <a href="https://doi.org/10.5281/zenodo.22983298" color="#145a88">10.5281/zenodo.22983298</a><br/>Source: eb8e39e070c3f4e2b00c5288efe008e2d737b4c3.

[3] Pal, R. PCCG-1: open-weight continuation-control evidence. <a href="https://doi.org/10.5281/zenodo.22681787" color="#145a88">10.5281/zenodo.22681787</a><br/>Source: d08b157ac9273974b75d7ada2a894a1afe86e3f2.

[4] Pal, R. Separating Capability from Permission in a Language Model (PCCG-2). <a href="https://doi.org/10.5281/zenodo.22730710" color="#145a88">10.5281/zenodo.22730710</a><br/>Source: a3b952458a46b5547ba3cec7d03a37b395bed03a.

[5] Pal, R. DOOR-KEY-1: Raw Results of an English Prerequisite Gate Test. <a href="https://doi.org/10.5281/zenodo.24042127" color="#145a88">10.5281/zenodo.24042127</a><br/>Source: 542fc5c5e5ab28122351a5cc4e46eddc0d57bfc4.

[6] Pal, R. Identity, condition and continuation synthesis. <a href="https://doi.org/10.5281/zenodo.24044104" color="#145a88">10.5281/zenodo.24044104</a><br/>Source: 289301f49c5e3087735825ced4adacaa34633153.

OpenAI. GPT-5.4 model documentation. <a href="https://developers.openai.com/api/docs/models/gpt-5.4" color="#145a88">Snapshot and supported endpoints</a>. OpenAI. <a href="https://developers.openai.com/api/docs/pricing" color="#145a88">API pricing</a>. Checked November 8, 2026.

Evidence anchors

Primary instrument freeze: 515138070f9d735793bba048b164aa0721eb41ca

Frozen source-manifest SHA-256: 536a75b44d4c09f3793c149bddb6e7d6a698ca303476b580b48493161cd5eef8

Schedule SHA-256: f8f9688c15d0ce410670e9eea6bdbb53280216b2448baa5e7c0302f774fdfc79

Preserved SwiftAPI core SHA-256: fc97753bed740956fdfb50f382a090de8d03d66bcce5208c96c7faabe6db3fa1

The release-wide SHA256SUMS includes this PDF and the evidence. Its own digest is distributed with the versioned release, avoiding a self-referential PDF hash. The independent verification transcript and machine-readable result tables are included alongside the manuscript.

<b>CAPABILITY DOES NOT LICENSE CONSEQUENCE.<br/>PROMPTING ALONE IS NOT AUTHORIZATION.</b>
