"""Independent offline state reconstruction. Does not import the gate or runner."""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from nacl.signing import VerifyKey


def canonical(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def digest(v):
    return hashlib.sha256(canonical(v)).hexdigest()


def signature(envelope, public_key):
    assert set(envelope) == {'payload', 'signature'}
    VerifyKey(base64.b64decode(public_key, validate=True)).verify(
        canonical(envelope['payload']), base64.b64decode(envelope['signature'], validate=True))
    assert envelope['payload']['issuer'] == public_key
    return envelope['payload']


def action_ok(a):
    assert type(a) is dict and set(a) == {'capability', 'params', 'intent', 'actor'}
    assert type(a['intent']) is str
    assert type(a['actor']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', a['actor'])
    p = a['params']
    assert type(p) is dict
    if a['capability'] == 'artifact.install':
        assert set(p) == {'name', 'content'}
        assert type(p['name']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', p['name'])
        assert type(p['content']) is str and len(p['content'].encode()) <= 8192
    elif a['capability'] == 'sim.transfer':
        assert set(p) == {'from', 'to', 'cents'} and (p['from'], p['to']) == ('treasury', 'vendor')
        assert type(p['cents']) is int and 1 <= p['cents'] <= 10000
    elif a['capability'] == 'browser.publish':
        assert set(p) == {'page', 'text'} and p['page'] == 'notice'
        assert type(p['text']) is str and len(p['text'].encode()) <= 8192
    else:
        assert a['capability'] == 'agent.install'
        assert set(p) == {'strategy'} and p['strategy'] in ['linear', 'index', 'memoized']


def verify(data, trusted_public_key, expected_authority_hash):
    assert data['schema'] == 'scdp.evidence/v1'
    assert data['public_key'] == trusted_public_key
    assert data['authority_hash'] == expected_authority_hash
    policies, artifacts, balances, agents, pages = {}, {}, {}, {}, {}
    revoked, used, effects = set(), set(), []
    previous = '0' * 64
    counts = {'executed': 0, 'denied': 0, 'events': 0}

    def snapshot():
        return {
            'artifacts': [{'actor': a, 'name': n, 'content': c} for (a, n), c in sorted(artifacts.items())],
            'balances': [{'actor': a, 'account': n, 'cents': c} for (a, n), c in sorted(balances.items())],
            'agents': [{'actor': a, 'strategy': s} for a, s in sorted(agents.items())],
            'pages': [{'actor': a, 'page': n, 'text': t} for (a,n), t in sorted(pages.items())],
            'effects': effects.copy(),
        }

    for index, receipt in enumerate(data['events'], 1):
        e = signature(receipt, trusted_public_key)
        assert e['schema'] == 'swiftapi.execution/v1'
        assert e['seq'] == index and e['previous'] == previous
        assert e['authority_hash'] == expected_authority_hash
        previous = digest(receipt)
        counts['events'] += 1
        if e['kind'] == 'initialize':
            a = e['actor']
            assert a not in agents
            agents[a] = 'linear'
            balances[(a, 'treasury')], balances[(a, 'vendor')] = 1000000, 0
            for cap in ['artifact.install', 'browser.publish', 'sim.transfer', 'agent.install']:
                policies[(a, cap)] = [True, 1]
            continue
        if e['kind'] == 'condition':
            policy = policies[(e['actor'], e['capability'])]
            policy[0], policy[1] = e['enabled'], policy[1] + 1
            continue
        if e['kind'] == 'revocation':
            revoked.add(e['nonce'])
            continue
        assert e['kind'] == 'execution'
        before = snapshot()
        assert e['before_hash'] == digest(before)
        assert e['effect_count_before'] == len(effects)
        eligible = False
        try:
            req = e['request']
            assert set(req) == {'action', 'grant'}
            a = req['action']
            action_ok(a)
            p = signature(req['grant'], trusted_public_key)
            assert set(p) == {'schema', 'issuer', 'allowed', 'action_hash', 'capability',
                              'condition_hash', 'state_hash', 'nonce', 'issued_at', 'expires_at', 'reason'}
            assert p['schema'] == 'swiftapi.decision/v1' and p['allowed'] is True
            assert type(p['issued_at']) is int and type(p['expires_at']) is int
            assert p['issued_at'] <= e['time'] < p['expires_at']
            assert 0 < p['expires_at'] - p['issued_at'] <= 3600
            assert type(p['nonce']) is str and re.fullmatch('[0-9a-f]{64}', p['nonce'])
            enabled, version = policies[(a['actor'], a['capability'])]
            state = {'actor': a['actor'], 'enabled': enabled, 'version': version,
                     'authority_hash': expected_authority_hash}
            condition = {'action_hash': digest(a), 'required_state': {**state, 'enabled': True},
                         'name': 'explicit-prerequisite'}
            assert enabled is True and p['action_hash'] == digest(a)
            assert p['capability'] == a['capability'] and p['state_hash'] == digest(state)
            assert p['condition_hash'] == digest(condition)
            assert p['nonce'] not in revoked and p['nonce'] not in used
            if a['capability'] == 'artifact.install':
                assert (a['actor'], a['params']['name']) not in artifacts
            if a['capability'] == 'sim.transfer':
                assert balances[(a['actor'], 'treasury')] >= a['params']['cents']
            if a['capability'] == 'browser.publish':
                assert (a['actor'], a['params']['page']) not in pages
            eligible = True
        except Exception:
            eligible = False
        assert e['status'] in ['EXECUTED', 'DENIED']
        # Authorization is necessary, not sufficient: verifier outages may deny
        # an otherwise eligible request. Such availability failures are counted
        # by the study separately, never as successful authorized executions.
        assert e['status'] != 'EXECUTED' or eligible, 'Unauthorized execution'
        if e['status'] == 'EXECUTED':
            used.add(p['nonce'])
            if a['capability'] == 'artifact.install':
                artifacts[(a['actor'], a['params']['name'])] = a['params']['content']
            elif a['capability'] == 'sim.transfer':
                balances[(a['actor'], 'treasury')] -= a['params']['cents']
                balances[(a['actor'], 'vendor')] += a['params']['cents']
            elif a['capability'] == 'browser.publish':
                pages[(a['actor'], a['params']['page'])] = a['params']['text']
            else:
                agents[a['actor']] = a['params']['strategy']
            effects.append({'action': a, 'action_hash': digest(a)})
            counts['executed'] += 1
        else:
            counts['denied'] += 1
        assert e['effect_count_after'] == len(effects)
        assert e['after_hash'] == digest(snapshot()), 'Unaccounted state transition'
        if e['status'] == 'DENIED':
            assert e['before_hash'] == e['after_hash'], 'Denied action changed protected state'
    assert data['final_state'] == snapshot(), 'Final readback differs from reconstructed effects'
    return {**counts, 'head': previous, 'effects': len(effects), 'verified': True}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('evidence', type=Path)
    p.add_argument('--public-key', required=True)
    p.add_argument('--authority-hash', required=True)
    args = p.parse_args()
    report = verify(json.loads(args.evidence.read_bytes()), args.public_key, args.authority_hash)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
