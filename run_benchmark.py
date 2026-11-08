"""Local-only SCDP-1 trials; primary execution requires a published preregistration."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import io
import tarfile
import urllib.request

from cases import DOMAINS, SCENARIOS, run_case
from gate import Gate, canonical, digest
from improvements import improvement_study
from verify_evidence import verify

ROOT = Path(__file__).resolve().parent


def write(path, data):
    path.write_bytes(json.dumps(data, ensure_ascii=False, indent=2).encode() + b'\n')


def check_registration(path):
    registration = json.loads(path.read_bytes())
    with urllib.request.urlopen('https://zenodo.org/api/records/' + str(registration['record_id']), timeout=30) as f:
        record = json.load(f)
    assert record.get('is_published') is True or record.get('submitted') is True
    assert record['doi'] == registration['doi']
    manifest = json.loads((ROOT / 'FREEZE.json').read_bytes())
    for name, expected in manifest['files'].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    assert registration['freeze_sha256'] == hashlib.sha256((ROOT / 'FREEZE.json').read_bytes()).hexdigest()
    entry = next(x for x in record['files'] if x['key'] == registration['filename'])
    with urllib.request.urlopen(entry['links'].get('content', entry['links'].get('self')), timeout=60) as f:
        published = f.read()
    assert hashlib.sha256(published).hexdigest() == registration['archive_sha256']
    with tarfile.open(fileobj=io.BytesIO(published), mode='r:*') as archive:
        freezes = [m for m in archive.getmembers() if m.name.endswith('/FREEZE.json') or m.name == 'FREEZE.json']
        assert len(freezes) == 1
        assert archive.extractfile(freezes[0]).read() == (ROOT / 'FREEZE.json').read_bytes()
        prefix = freezes[0].name[:-len('FREEZE.json')]
        for name, expected in manifest['files'].items():
            assert hashlib.sha256(archive.extractfile(prefix + name).read()).hexdigest() == expected, name
    return {'doi': registration['doi'], 'record_created': record['created'],
            'archive_sha256': registration['archive_sha256']}


def run(output, mode, registration=None):
    if output.exists():
        raise SystemExit('New empty output path required; no overwrites or resume')
    prereg = check_registration(registration) if mode == 'primary' else None
    output.mkdir(parents=True)
    root = Path(tempfile.mkdtemp(prefix='scdp-private-'))
    g = Gate(root)
    schedule = json.loads((ROOT / 'SCHEDULE.json').read_bytes())
    if mode == 'development':
        schedule = [{'domain': d, 'scenario': s, 'replicate': 0} for d in DOMAINS for s in SCENARIOS]
    started = datetime.now(timezone.utc).isoformat()
    rows = []
    try:
        for i, slot in enumerate(schedule):
            row = run_case(g, slot['domain'], slot['scenario'], f'trial-{i:04}')
            row['slot'] = slot
            rows.append(row)
            write(output / f'case-{i:04}.json', row)
        improvement = improvement_study(g)
        write(output / 'improvements.json', improvement)
    finally:
        data = g.export()
        write(output / 'evidence.json', data)
        write(output / 'run.json', {'mode': mode, 'started_utc': started,
              'finished_utc': datetime.now(timezone.utc).isoformat(), 'registration': prereg,
              'public_key': g.public_key, 'authority_hash': g.authority_hash,
              'scheduled_cases': len(schedule), 'completed_cases': len(rows), 'api_spend_usd': 0})
        with (output / 'events.jsonl').open('wb') as f:
            for event in data['events']:
                f.write(canonical(event) + b'\n')
    report = verify(data, g.public_key, g.authority_hash)
    report.update({'case_count': len(rows), 'cases_passed': sum(x['passed'] for x in rows),
                   'failed_cases': [x for x in rows if not x['passed']],
                   'mode': mode, 'api_spend_usd': 0})
    write(output / 'verification.json', report)
    print(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=['development', 'primary'], required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--registration', type=Path)
    a = p.parse_args()
    if a.mode == 'primary' and a.registration is None:
        p.error('Public preregistration required')
    run(a.output, a.mode, a.registration)
