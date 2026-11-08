import copy
import json
import sqlite3
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest
from cases import DOMAINS, SCENARIOS, action_for, run_case
from gate import Gate, InvalidEnvelope, canonical
from improvements import improvement_study
from server import make_server
from verify_evidence import verify


@pytest.mark.parametrize('domain', DOMAINS)
@pytest.mark.parametrize('scenario', SCENARIOS)
def test_cross_domain(tmp_path, domain, scenario):
    root = tmp_path / 'state'
    g = Gate(root)
    row = run_case(g, domain, scenario, 'fixture')
    assert row['passed'], row
    data = g.export()
    assert verify(data, g.public_key, g.authority_hash)['verified']
    assert Gate(root).snapshot() == g.snapshot()


def test_improvements(tmp_path):
    g = Gate(tmp_path / 'state')
    result = improvement_study(g)
    assert all(s['accepted'] for s in result['stages'])
    assert result['contribution_test']
    assert result['authority_hash_before'] == result['authority_hash_after']
    assert result['authority_mutation_status'] == 'DENIED'
    assert verify(g.export(), g.public_key, g.authority_hash)['verified']


@pytest.mark.parametrize('attack', ['signature', 'state', 'drop', 'reorder', 'key', 'chain'])
def test_tamper_detected(tmp_path, attack):
    g = Gate(tmp_path / 'state')
    run_case(g, 'finance', 'satisfied', 'a')
    d = copy.deepcopy(g.export())
    if attack == 'signature':
        d['events'][1]['signature'] = 'AA=='
    elif attack == 'state':
        d['final_state']['balances'][0]['cents'] += 1
    elif attack == 'drop':
        d['events'].pop()
    elif attack == 'reorder':
        d['events'].reverse()
    elif attack == 'key':
        d['public_key'] = 'AA=='
    else:
        d['events'][1]['payload']['previous'] = 'f' * 64
    with pytest.raises(Exception):
        verify(d, g.public_key, g.authority_hash)


def test_http_surface(tmp_path):
    g = Gate(tmp_path / 'state')
    g.initialize('http')
    a = action_for('browser', 'http')
    s = make_server(g)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    base = f'http://127.0.0.1:{s.server_port}'
    try:
        def post(path, body, headers=None):
            return urlopen(Request(base + path, data=body, headers=headers or {}), timeout=5)
        with pytest.raises(HTTPError):
            post('/approve', b'{}')
        with pytest.raises(HTTPError):
            post('/execute', b'{}', {'Origin': 'https://attacker.invalid'})
        with pytest.raises(HTTPError):
            post('/execute', b'{"action":1,"action":2}')
        denied = json.load(post('/execute', canonical({'action': a, 'grant': None})))
        assert denied['payload']['status'] == 'DENIED'
        granted = json.load(post('/execute', canonical({'action': a, 'grant': g.authorize(a)})))
        assert granted['payload']['status'] == 'EXECUTED'
        assert len(g.snapshot()['pages']) == 1
    finally:
        s.shutdown(); s.server_close(); t.join()


def test_transaction_rollback(tmp_path, monkeypatch):
    g = Gate(tmp_path / 'state')
    g.initialize('rollback')
    a = action_for('finance', 'rollback')
    grant = g.authorize(a)
    before = g.snapshot()
    original = g._apply
    def broken(db, action, verified):
        original(db, action, verified)
        raise RuntimeError('injected interruption before commit')
    monkeypatch.setattr(g, '_apply', broken)
    with pytest.raises(RuntimeError):
        g.execute({'action': a, 'grant': grant})
    assert g.snapshot() == before
    monkeypatch.setattr(g, '_apply', original)
    assert g.execute({'action': a, 'grant': grant})['payload']['status'] == 'EXECUTED'
    assert verify(g.export(), g.public_key, g.authority_hash)['verified']


def test_mutated_governing_policy_denied_on_restart(tmp_path):
    g = Gate(tmp_path / 'state')
    with g.db() as db:
        db.execute("UPDATE metadata SET value='tampered' WHERE k='authority_hash'")
    with pytest.raises(Exception):
        Gate(tmp_path / 'state')


def test_missing_verification_function_fails_closed(tmp_path, monkeypatch):
    g = Gate(tmp_path / 'state')
    g.initialize('unavailable')
    a = action_for('finance', 'unavailable')
    grant = g.authorize(a)
    before = g.snapshot()
    monkeypatch.setattr('gate.verify_decision', None)
    assert g.execute({'action': a, 'grant': grant})['payload']['status'] == 'DENIED'
    assert g.snapshot() == before


@pytest.mark.parametrize('change', [{'cents': 126}, {'cents': -1}, {'cents': True},
                                  {'to': 'attacker'}, {'from': 'vendor'}, {'cents': 10001}])
def test_financial_scope_is_exact(tmp_path, change):
    g = Gate(tmp_path / 'state')
    g.initialize('scope')
    a = action_for('finance', 'scope')
    grant = g.authorize(a)
    before = g.snapshot()
    a['params'].update(change)
    assert g.execute({'action': a, 'grant': grant})['payload']['status'] == 'DENIED'
    assert g.snapshot() == before
    assert verify(g.export(), g.public_key, g.authority_hash)['verified']


def test_adapter_rejects_absent_verified_context(tmp_path):
    from gate import validate_action
    g = Gate(tmp_path / 'state')
    g.initialize('adapter')
    before = g.snapshot()
    with g.db() as db:
        with pytest.raises(Exception):
            g.financial_adapter.apply(db, validate_action(action_for('finance', 'adapter')), None)
    assert g.snapshot() == before
