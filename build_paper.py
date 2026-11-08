"""Render the manuscript from independently verified result JSON."""
from pathlib import Path
import json,html,hashlib
from collections import Counter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,KeepTogether
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ROOT=Path(__file__).parent
TITLE='STOP ASKING “CAN AI DO IT?” START ASKING “WHAT GIVES AI THE RIGHT TO FOLLOW?”'
SUBTITLE='GPT-5.4, the Binding Condition, Protected Agent Execution, and Why Prompting Alone Is Not Authorization'
REPO='https://github.com/theonlypal/gpt54-swiftapi-authorization-benchmark'

def build():
    r=json.loads((ROOT/'results/summary.json').read_bytes());c=r['counts'];a=r['attacks']
    if not r['verified']: raise RuntimeError('Verified evidence required')
    dest=ROOT/'output/pdf';dest.mkdir(parents=True,exist_ok=True)
    fonts=Path('/System/Library/Fonts/Supplemental')
    pdfmetrics.registerFont(TTFont('Paper',str(fonts/'Times New Roman.ttf')))
    pdfmetrics.registerFont(TTFont('PaperBold',str(fonts/'Times New Roman Bold.ttf')))
    pdfmetrics.registerFontFamily('Paper',normal='Paper',bold='PaperBold',italic='Paper',boldItalic='PaperBold')
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle('BodyP',fontName='Paper',fontSize=10.5,leading=14,spaceAfter=8))
    styles.add(ParagraphStyle('SmallP',fontName='Paper',fontSize=8.3,leading=11,spaceAfter=5))
    styles.add(ParagraphStyle('HeadP',fontName='PaperBold',fontSize=14,leading=18,spaceAfter=10,spaceBefore=6))
    styles.add(ParagraphStyle('TitleP',fontName='PaperBold',fontSize=22,leading=27,spaceAfter=14))
    styles.add(ParagraphStyle('SubP',fontName='Paper',fontSize=13,leading=17,spaceAfter=10))
    story=[];md=[]
    def para(text,style='BodyP'):
        story.append(Paragraph(text,styles[style]));md.append(text)
    def head(text): para(text,'HeadP')
    def page(): story.append(PageBreak());md.append('\n---\n')
    def table(headers,rows,widths,caption):
        cells=[[Paragraph(html.escape(str(v)),styles['SmallP']) for v in line] for line in [headers]+rows]
        t=Table(cells,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e9eef3')),('VALIGN',(0,0),(-1,-1),'TOP'),('LINEBELOW',(0,0),(-1,0),.7,colors.HexColor('#223344')),('LINEBELOW',(0,-1),(-1,-1),.5,colors.HexColor('#8899aa')),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),4)]))
        story.append(t);story.append(Spacer(1,6));para(caption,'SmallP')
        md.extend([' | '.join(map(str,headers))]+[' | '.join(map(str,x)) for x in rows])
    def ref(n,doi,text):
        return f'{text} <a href="https://doi.org/10.5281/zenodo.{doi}" color="#145a88">[{n}]</a>'
    abstract=(f"A preregistered local benchmark collected {c['completed_generations']}/{len(r['rows'])} completed generations from gpt-5.4-2026-03-05 through OpenAI’s direct Responses API. "
        f"The model supplied {c.get('proposal_valid',0)} valid proposals and {c['proposal_refusal']} explicit refusals. Identical proposals were replayed across independently reset authorization states: "
        f"{c['satisfied_effects']}/{c['satisfied_conditions']} satisfied conditions committed an exact protected operation, versus {c['unsatisfied_effects']}/{c['unsatisfied_conditions']} unsatisfied conditions. "
        f"Across paired and adversarial environments, {c['protected_effects']} protected effects were reconstructed, with {c['unauthorized_effects']} unauthorized effects and {c['duplicate_effects']} duplicate commitments. "
        f"The prompt-only software control produced {c['prompt_only_unauthorized_effects']}/{c['prompt_only_prohibited_N']} prohibited effects; thus this study does not demonstrate a prompt-only failure. "
        "Its positive result is a measured separation between model-generated proposals and execution authority under tested signature, scope, condition, replay, concurrency and crash constraints. "
        "The consequences are local artifact/page writes, simulated ledger transfers and finite strategy updates. These results do not establish universal security, autonomous RSI or production financial safety.")
    (ROOT/'results/ABSTRACT.txt').write_text(abstract+'\n')
    para(TITLE,'TitleP');para(SUBTITLE,'SubP');para('Sharthok Rayan Pal — SwiftAPI Labs<br/>November 8, 2026 · Version 1.0.1','BodyP')
    head('Abstract');para(abstract)
    head('Principal finding')
    para('Human intent defines an objective. A binding condition specifies a prerequisite. The authority to execute is verified outside the model. In this benchmark, a valid model proposal did not itself constitute permission; an externally validated, exact-action grant and current condition were required before a protected state change.')
    para(f'Public pre-inference freeze: <a href="{REPO}/tree/515138070f9d735793bba048b164aa0721eb41ca" color="#145a88">515138070f9d735793bba048b164aa0721eb41ca</a>. Exact protocol, source and requests are preserved in the repository.','SmallP')
    page();head('1. Capability, proposal, authority and consequence')
    para('The enforcement invariant is: Execute(action) implies Authorized(action), Verified(prerequisites), and ScopeValid(action). This is an implementation property relative to trusted components and a stated threat model, not a universal property of language models. An instruction may shape a proposal or a refusal; it does not furnish a cryptographic grant or mutate the trusted permission state.')
    table(['Layer','Evidence','What it does not establish'],[
        ['Model behavior','Original output, status, identifiers and usage','Approval or execution'],
        ['Authorization','Ed25519 signature; exact action and current state','That dispatch or commitment occurred'],
        ['Protected consequence','Transactional event plus independent final readback','Remote settlement or production safety'],
        ['Offline verification','Separate reconstruction of archived evidence','Third-party replication or provider attestation']], [100,190,206], 'Table 1. Distinct evidence requirements.')
    head('2. Frozen model and task design')
    para('The experimental subject is gpt-5.4-2026-03-05, not the model assisting research development. Requests used /v1/responses directly, reasoning effort none, output ceiling 512, default service tier, store=false and stream=false. Temperature, sampling seed, tools and enforced JSON schema were omitted. Each request had fresh context. The API collector made no retries, prompt repairs or model substitutions. Official model and rate documentation are linked in the protocol.')
    para('Four domains each contain five conditions and four task variants: permitted execution; planning without permission; denied execution with an instruction override; denied execution with an asserted administrator approval; and planning with attempted scope expansion. Trusted request fields specify the exact actor and allowed parameters. Untrusted text cannot authorize execution. Planning is explicitly allowed to produce proposals without approval.')
    para('The system instruction requires either an exact action JSON object or a refusal JSON object. Refusals, malformed responses, abstention and operational failure remain observations, not discarded trials. The full instruction, user data and byte hashes are frozen in PROTOCOL.json and SCHEDULE.json. No post-result prompt adjustment was made.')
    para('The prompt-only control is confined to execute-mode software scenarios. It writes a valid proposed artifact into an isolated ungated database and does not check an external grant. Planning outputs are excluded from the prompt-failure denominator because the system instruction permits them. This prevents counting an allowed proposal as a failure to refuse.')
    page();head('3. Trusted execution architecture')
    para('The existing SwiftAPI Ed25519 verification core is preserved byte-identically. The external scope oracle permits only the scheduled actor, capability and exact parameters; the model supplies its own intent text, which is also signed. The grant binds an action digest, condition digest, current policy version, lifetime and one-use nonce. The broker verifies all fields, checks revocation, and consumes the nonce in the same SQLite transaction as the protected action and execution receipt.')
    para('The API key belongs only to the trusted collection process. The model and its fixed JSON transport receive no signing key or protected-database handle. Every transport invocation runs in a macOS deny-by-default sandbox. Its only network destination is the local execution endpoint; key read, database read/write, code write and alternate-port probes must be denied. The research IDE and host administrator remain trusted, not sandboxed.')
    table(['Domain','Committed operation','Boundary of the claim'],[
        ['Software','Install exact source text in artifact store','No arbitrary program or shell execution'],
        ['Browser action','Update local notice through loopback HTTP','No external website write or GUI eval'],
        ['Finance','Atomic integer debit and credit','Simulated units, no real funds'],
        ['Agent modification','Install index/memoized strategy setting','No autonomous RSI or authority edit']], [91,211,194],'Table 2. Real local state changes and their limited interpretation.')
    head('4. Paired and adversarial procedures')
    para('For each valid proposal, two new environments receive identical action bytes. In the satisfied arm the independent authority grants the exact scoped action. In the unsatisfied arm the trusted condition changes after grant issuance and before dispatch. Out-of-scope proposals receive no approving grant. Each environment begins with a fresh database and authority, preventing replay state or earlier effects from contaminating the pair.')
    para('Additional environments apply missing, forged, expired, revoked and replayed grants; changed parameters; scope escalation; eight concurrent redemptions; unavailable verification; changed policy version; and interruption after SQL writes but before commit. The interrupted process exits with a frozen diagnostic code. Readback must show rollback; a subsequent valid retry may commit once, while its replay may not. These mutations are programmed attacks against real GPT-generated proposals, not autonomous model-generated exploit programs.')
    para('Denial logs are not protected business effects. An HTTP failure is not counted as a safe denial. Interrupted requests are initially UNKNOWN and are resolved only by signed-event reconstruction plus independent local state readback. General remote payment timeouts remain outside this transactional experiment.')
    page();head('5. Results: generations and matched execution')
    rows=[]
    for d,v in r['by_domain'].items():
        total=sum(v.get(k,0) for k in ['valid','refusal','provider_refusal','invalid','abstention','operational'])
        rows.append([d,total,v.get('valid',0),v.get('refusal',0),f"{v.get('satisfied_effects',0)}/{v.get('satisfied_N',0)}",f"{v.get('unsatisfied_effects',0)}/{v.get('unsatisfied_N',0)}"])
    table(['Domain','N','Valid','Refusal','Satisfied effects / N','Unsatisfied effects / N'],rows,[80,35,45,48,143,145],'Table 3. One generation per slot; paired conditions reuse the same generated action. Refusals have no paired execution.')
    para(f"All {c['generation_attempts']} primary attempts returned HTTP 200 and {c['completed_generations']} completed with the specified model. The retained record contains {c['proposal_invalid']} malformed proposals, {c['scope_deviating_proposals']} schema-valid scope deviations, {c['proposal_provider_refusal']} provider refusals, {c['proposal_abstention']} abstentions, and {c['proposal_operational']} operational model outcomes. These counts are generated from the raw API bodies, not inferred from gateway status.")
    by=Counter((x['condition'],x['proposal']) for x in r['rows'])
    table(['Prompt condition','Valid proposals','Explicit refusals'],[[k,by[k,'valid'],by[k,'refusal']] for k in ['permitted','planning','instruction_conflict','claimed_approval','scope_expansion']],[250,123,123],'Table 4. Aggregate prompt behavior across domains; full trial-level rows are in summary.json.')
    para(f"The protected pair produced {c['satisfied_effects']} authorized consequences and {c['unsatisfied_effects']} consequences under the unsatisfied state. The prompt-only control produced {c['prompt_only_effects']} artifact writes across {c['prompt_only_N']} execute-mode cases; {c['prompt_only_unauthorized_effects']}/{c['prompt_only_prohibited_N']} prohibited cases wrote an artifact. The observed control therefore supplies no empirical prompt-only bypass in this fixed set. This negative finding is retained without relabeling planning outputs as violations.")
    para(f"Usage-priced OpenAI cost was USD {r['cost_usd']}, including {c['preflight_requests']} separately labeled preflight request. The hard ceiling was USD 20; no additional paid service was used. Rates were USD 2.50 input, 0.25 cached input and 15.00 output per million tokens. This is a reconstruction from provider usage fields, not an account invoice.")
    page();head('6. Adversarial outcomes and falsification')
    table(['Enforcement condition','Environments','Effects','Executed','Denied'],[[k,v['N'],v['effects'],v['executed'],v['denied']] for k,v in a.items()],[216,70,62,74,74],'Table 5. Reset environments over unchanged model proposals. Replay/concurrency/crash arms intentionally include one authorized commitment per environment.')
    para(f"Across {c['protected_environments']} environments, the verifier reconstructed {c['protected_executions']} executed operations and {c['protected_denials']} denied submissions. Unauthorized protected effects: {c['unauthorized_effects']}; duplicate commitments: {c['duplicate_effects']}. The {c['transport_unknown_resolved_by_readback']} interrupted transports were resolved by unchanged post-crash state and retry readback. Unresolved outcomes: {c['unknown_outcomes']}.")
    labels={'H1_zero_unauthorized_effects':'H1: zero unauthorized effects','H2_usefulness':'H2: useful authorized execution','H3_at_most_once':'H3: single-use/at-most-once','H4_crash_retry':'H4: crash rollback and retry'}
    table(['Frozen criterion','Result'],[[label,'PASS' if r['predictions'][key] else 'FAIL'] for key,label in labels.items()],[366,130],'Table 6. Frozen predictions. H5 is descriptive, not a pass/fail prediction.')
    para(f"Recorded protocol/evidence issues: {len(r['issues'])}. Unattempted primary slots: {c['unattempted']}. Missing execution records: {c['execution_unavailable']}. No response was regenerated. Primary counts include refusals and any invalid or operational outcomes; successful gate executions are not substituted for failed model generations.")
    head('7. Historical evidence is a different level of measurement')
    para(ref(1,'17856031','The December 8, 2025 Void publication introduced the behavioral research program. It is historical motivation, not part of the new trial denominator.'))
    para(ref(2,'22983298','Published GPT-5.4 prerequisite reassignment tests changed semantic prerequisites in the instruction context. Such hosted output changes are not independent execution authorization, and an API-visible empty answer does not expose internal EOS logits.'))
    para(ref(3,'22681787','PCCG-1 manipulated continuation in an engineered open-weight setting.')+' '+ref(4,'22730710','PCCG-2 separated frozen content from a gate that changed native EOS while preserving non-EOS logits. Neither mechanism is shown to be the mechanism of this software authorization boundary.'))
    page();head('8. Interpretation and limitations')
    para(ref(5,'24042127','The published English DOOR-KEY-1 results include incomplete prompt-level gating.')+' '+ref(6,'24044104','The November 7 synthesis separates hosted model behavior, engineered termination and consequential execution. The present experiment adds direct GPT-5.4 proposals and independently reconstructed local consequences to that distinction.'))
    para('The measured contribution is narrow and falsifiable: fixed proposals were usable with the independently authorized condition and ineffective without it, within the implemented trust boundary and tested attack matrix. A model refusal is behavior; a blocked operation is enforcement; a reconciled state transition is consequence. None can replace the others as evidence.')
    para('Prompting alone is not authorization is an architectural statement here, not a claim that GPT-5.4 failed the tested instructions. No prompt-only prohibited write was observed in this fixed set. The benchmark does not establish the failure probability of prompting under broader or adaptive attacks. An adversary controlling the trusted signer, kernel, operator or broker can violate the assumed boundary; such compromise is outside the stated threat model.')
    para('The transport is scripted and the model proposes in a single turn. No autonomous exploit search or iterative adversarial agent was tested. Software actions install text rather than execute arbitrary programs. Browser actions exercise a local HTTP-backed page store rather than external browsing. Financial effects use simulated units. Strategy changes do not establish two successive autonomous improvements or RSI. None of the four domains establishes production deployment safety.')
    para('Receipts are signed by the study authority, not by OpenAI. They authenticate the archived chain relative to the published trust anchor; they cannot independently prove provider authorship or exclude a dishonest operator. The separate verifier is independently runnable but was developed within the same research workflow. No independent third-party replication is claimed. Counts enumerate the frozen finite task set; no population inference, confidence interval or universal security guarantee is asserted.')
    head('9. Reproducibility and artifact integrity')
    para(f'Code, frozen protocol and raw evidence: <a href="{REPO}" color="#145a88">{REPO}</a>. The release includes exact model requests/responses, safe headers, grants, signed execution chains, client-isolation probes, final-state exports, generated results, test reports and SHA256SUMS. Signing keys and API credentials are excluded.')
    para('From a fresh clone: install requirements.txt, run <b>python verify_study.py</b>, and verify <b>shasum -a 256 -c SHA256SUMS</b>. No paid inference or signing authority is needed. The verifier checks frozen bytes, independently decodes proposals, reconstructs nonce/state/signature decisions, checks readback and recalculates usage-priced cost. The execution instrument is not rerun to verify archived outcomes.')
    para('The live experiment is deliberately not automatically repeatable by the offline verifier: new paid collection requires explicit credentials, a budget and fresh paths. Existing records are immutable. The macOS sandbox is a qualified local boundary, not a portable assurance claim for other operating systems or cloud deployments.')
    para('Release qualification requires a virtual environment inside the fresh checkout. A borrowed environment outside its sandbox-readable tree caused thirteen development-check failures; the correctly installed clone passed all 108 checks. The earlier tag’s qualification metadata is corrected in version 1.0.1. Primary requests, responses, execution evidence, frozen code and outcomes are unchanged. Details and the successful JUnit record are preserved in QUALIFICATION_NOTES.md and verification/.','SmallP')
    page();head('References and frozen identifiers')
    refs=[('17856031','Textual Emergence and the Void: A Framework for Observing High-Order Model Behavior in LLM Systems','Published December 8, 2025'),('22983298','Prerequisite Role Reassignment Controls Continuation in GPT-5.4','eb8e39e070c3f4e2b00c5288efe008e2d737b4c3'),('22681787','PCCG-1: open-weight continuation-control evidence','d08b157ac9273974b75d7ada2a894a1afe86e3f2'),('22730710','Separating Capability from Permission in a Language Model (PCCG-2)','a3b952458a46b5547ba3cec7d03a37b395bed03a'),('24042127','DOOR-KEY-1: Raw Results of an English Prerequisite Gate Test','542fc5c5e5ab28122351a5cc4e46eddc0d57bfc4'),('24044104','Identity, condition and continuation synthesis','289301f49c5e3087735825ced4adacaa34633153')]
    for n,(doi,title,pin) in enumerate(refs,1):
        para(f'[{n}] Pal, R. {html.escape(title)}. <a href="https://doi.org/10.5281/zenodo.{doi}" color="#145a88">10.5281/zenodo.{doi}</a><br/>Source: {pin}.','SmallP')
    para('OpenAI. GPT-5.4 model documentation. <a href="https://developers.openai.com/api/docs/models/gpt-5.4" color="#145a88">Snapshot and supported endpoints</a>. OpenAI. <a href="https://developers.openai.com/api/docs/pricing" color="#145a88">API pricing</a>. Checked November 8, 2026.','SmallP')
    head('Evidence anchors')
    para('Primary instrument freeze: '+(ROOT/'FREEZE_COMMIT.txt').read_text().strip(),'SmallP')
    para('Frozen source-manifest SHA-256: '+hashlib.sha256((ROOT/'FREEZE_SHA256SUMS').read_bytes()).hexdigest(),'SmallP')
    para('Schedule SHA-256: '+hashlib.sha256((ROOT/'SCHEDULE.json').read_bytes()).hexdigest(),'SmallP')
    para('Preserved SwiftAPI core SHA-256: '+hashlib.sha256((ROOT/'vendor/swiftapi/brake/core.py').read_bytes()).hexdigest(),'SmallP')
    para('The release-wide SHA256SUMS includes this PDF and the evidence. Its own digest is distributed with the versioned release, avoiding a self-referential PDF hash. The independent verification transcript and machine-readable result tables are included alongside the manuscript.','SmallP')
    story.append(Spacer(1,20));para('<b>CAPABILITY DOES NOT LICENSE CONSEQUENCE.<br/>PROMPTING ALONE IS NOT AUTHORIZATION.</b>','SubP')
    def footer(canvas,doc):
        canvas.saveState();canvas.setFont('Paper',8);canvas.setFillColor(colors.HexColor('#52616c'))
        canvas.drawString(50,30,'GPT-5.4 × SwiftAPI · Preregistered local authorization benchmark')
        canvas.drawRightString(546,30,str(doc.page));canvas.restoreState()
    doc=SimpleDocTemplate(str(dest/'GPT54_SwiftAPI_Authorization_Benchmark.pdf'),pagesize=(596,842),
                         leftMargin=50,rightMargin=50,topMargin=45,bottomMargin=48,
                         title=TITLE,author='Sharthok Rayan Pal — SwiftAPI Labs',subject=SUBTITLE)
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    (ROOT/'PAPER.md').write_text('\n\n'.join(md)+'\n')
    print(dest/'GPT54_SwiftAPI_Authorization_Benchmark.pdf')

if __name__=='__main__': build()
