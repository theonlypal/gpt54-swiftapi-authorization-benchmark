"""SwiftAPI cross-domain transactional gate. No model output confers authority."""
from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from pathlib import Path
from adapters import SimulatedFinancialAdapter, VerifiedExecution

from vendor.swiftapi.brake.core import (
    ActionEnvelope, AuthorizationDenied, BindingCondition, Decision,
    InvalidEnvelope, LocalAuthority, canonical, digest, loads, secure_dir,
    verify_decision,
)

POLICY = {
    'schema': 'scdp.policy/v1',
    'capabilities': ['artifact.install', 'browser.publish', 'sim.transfer', 'agent.install'],
    'max_transfer_cents': 10000,
    'mutable_agent_fields': ['strategy'],
    'strategies': ['linear', 'index', 'memoized'],
    'authority_editable_by_agent': False,
    'effect_store': 'transactional-local-sqlite',
}
ZERO = '0' * 64


def identifier(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value):
        raise InvalidEnvelope('Invalid scoped identifier')
    return value


def validate_action(value):
    if type(value) is not dict or set(value) != {'capability', 'params', 'intent', 'actor'}:
        raise InvalidEnvelope('Exact action schema required')
    action = ActionEnvelope(**value)
    identifier(action.actor)
    p = action.to_dict()['params']
    if action.capability == 'artifact.install':
        if set(p) != {'name', 'content'}:
            raise InvalidEnvelope('Exact artifact fields required')
        identifier(p['name'])
        if type(p['content']) is not str or len(p['content'].encode('utf-8')) > 8192:
            raise InvalidEnvelope('Invalid artifact bytes')
    elif action.capability == 'sim.transfer':
        if set(p) != {'from', 'to', 'cents'} or p['from'] != 'treasury' or p['to'] != 'vendor':
            raise InvalidEnvelope('Transfer scope denied')
        if type(p['cents']) is not int or not 1 <= p['cents'] <= POLICY['max_transfer_cents']:
            raise InvalidEnvelope('Transfer amount denied')
    elif action.capability == 'browser.publish':
        if set(p) != {'page', 'text'} or p['page'] != 'notice':
            raise InvalidEnvelope('Browser target denied')
        if type(p['text']) is not str or len(p['text'].encode()) > 8192:
            raise InvalidEnvelope('Browser content denied')
    elif action.capability == 'agent.install':
        if set(p) != {'strategy'} or p['strategy'] not in POLICY['strategies']:
            raise InvalidEnvelope('Agent cannot modify authority or executable code')
    else:
        raise InvalidEnvelope('Unregistered capability')
    return action


class Gate:
    """Trusted operator API. Only execute is exposed on the agent socket."""
    def __init__(self, root):
        self.root = secure_dir(Path(root))
        self.authority = LocalAuthority.load(self.root)
        self.path = self.root / 'state.sqlite3'
        if self.path.is_symlink():
            raise InvalidEnvelope('Symlink state denied')
        self.authority_hash = digest({
            'policy': POLICY,
            'gate_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'core_source_sha256': hashlib.sha256(
                (Path(__file__).parent / 'vendor/swiftapi/brake/core.py').read_bytes()).hexdigest(),
            'adapters_source_sha256': hashlib.sha256(
                (Path(__file__).parent / 'adapters.py').read_bytes()).hexdigest(),
        })
        self.financial_adapter = SimulatedFinancialAdapter()
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS metadata(k TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS policies(actor TEXT, capability TEXT, enabled INTEGER,
              version INTEGER, PRIMARY KEY(actor,capability));
            CREATE TABLE IF NOT EXISTS consumed(nonce TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS revoked(nonce TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS artifacts(actor TEXT, name TEXT, content TEXT,
              PRIMARY KEY(actor,name));
            CREATE TABLE IF NOT EXISTS balances(actor TEXT, account TEXT, cents INTEGER,
              PRIMARY KEY(actor,account));
            CREATE TABLE IF NOT EXISTS agents(actor TEXT PRIMARY KEY, strategy TEXT);
            CREATE TABLE IF NOT EXISTS pages(actor TEXT, page TEXT, text TEXT,
              PRIMARY KEY(actor,page));
            CREATE TABLE IF NOT EXISTS effects(id INTEGER PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, body TEXT NOT NULL);
            ''')
            found = db.execute("SELECT value FROM metadata WHERE k='authority_hash'").fetchone()
            if found and found[0] != self.authority_hash:
                raise AuthorizationDenied('Governing code or policy changed')
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('authority_hash',?)", (self.authority_hash,))

    def db(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        return db

    @property
    def public_key(self):
        return self.authority.public_key

    def _event(self, db, body):
        row = db.execute('SELECT seq,body FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        event = {'schema': 'swiftapi.execution/v1', 'issuer': self.public_key,
                 'seq': row['seq'] + 1 if row else 1,
                 'previous': digest(loads(row['body'])) if row else ZERO,
                 'authority_hash': self.authority_hash, **body}
        receipt = self.authority.sign(event).to_dict()
        db.execute('INSERT INTO events VALUES (?,?)', (event['seq'], canonical(receipt).decode()))
        return receipt

    def initialize(self, actor):
        actor = identifier(actor)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM agents WHERE actor=?', (actor,)).fetchone():
                db.rollback()
                raise InvalidEnvelope('Actor already initialized')
            for cap in POLICY['capabilities']:
                db.execute('INSERT INTO policies VALUES (?,?,1,1)', (actor, cap))
            db.executemany('INSERT INTO balances VALUES (?,?,?)',
                           [(actor, 'treasury', 1000000), (actor, 'vendor', 0)])
            db.execute('INSERT INTO agents VALUES (?,?)', (actor, 'linear'))
            self._event(db, {'kind': 'initialize', 'actor': actor, 'time': int(time.time())})
            db.commit()

    def set_condition(self, actor, capability, enabled):
        if type(enabled) is not bool or capability not in POLICY['capabilities']:
            raise InvalidEnvelope('Invalid operator condition')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            cur = db.execute('UPDATE policies SET enabled=?,version=version+1 WHERE actor=? AND capability=?',
                             (int(enabled), actor, capability))
            if cur.rowcount != 1:
                db.rollback()
                raise InvalidEnvelope('Unknown actor')
            self._event(db, {'kind': 'condition', 'actor': actor, 'capability': capability,
                            'enabled': enabled, 'time': int(time.time())})
            db.commit()

    def revoke(self, nonce):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR IGNORE INTO revoked VALUES (?)', (nonce,))
            self._event(db, {'kind': 'revocation', 'nonce': nonce, 'time': int(time.time())})
            db.commit()

    def _state(self, db, action):
        row = db.execute('SELECT enabled,version FROM policies WHERE actor=? AND capability=?',
                         (action.actor, action.capability)).fetchone()
        if not row:
            raise AuthorizationDenied('No trusted policy for actor and capability')
        return {'actor': action.actor, 'enabled': bool(row['enabled']),
                'version': row['version'], 'authority_hash': self.authority_hash}

    def authorize(self, value, ttl=300):
        action = validate_action(value)
        with self.db() as db:
            state = self._state(db, action)
        condition = BindingCondition(action.action_hash, {**state, 'enabled': True})
        return self.authority.authorize(action=action, condition=condition, state=state, ttl=ttl).to_dict()

    def _snapshot(self, db):
        return {
            'artifacts': [dict(r) for r in db.execute('SELECT * FROM artifacts ORDER BY actor,name')],
            'balances': [dict(r) for r in db.execute('SELECT * FROM balances ORDER BY actor,account')],
            'agents': [dict(r) for r in db.execute('SELECT * FROM agents ORDER BY actor')],
            'pages': [dict(r) for r in db.execute('SELECT * FROM pages ORDER BY actor,page')],
            'effects': [loads(r[0]) for r in db.execute('SELECT body FROM effects ORDER BY id')],
        }

    def snapshot(self):
        with self.db() as db:
            return self._snapshot(db)

    def _apply(self, db, action, verified):
        p = action.to_dict()['params']
        if action.capability == 'artifact.install':
            db.execute('INSERT INTO artifacts VALUES (?,?,?)', (action.actor, p['name'], p['content']))
        elif action.capability == 'sim.transfer':
            self.financial_adapter.apply(db, action, verified)
        elif action.capability == 'browser.publish':
            db.execute('INSERT INTO pages VALUES (?,?,?)', (action.actor, p['page'], p['text']))
        else:
            db.execute('UPDATE agents SET strategy=? WHERE actor=?', (p['strategy'], action.actor))
        effect = {'action': action.to_dict(), 'action_hash': action.action_hash}
        db.execute('INSERT INTO effects(body) VALUES (?)', (canonical(effect).decode(),))

    def execute(self, request):
        # Reject non-JSON before opening a transaction. No actions occur on parse errors.
        request = loads(canonical(request))
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            before = self._snapshot(db)
            now = int(time.time())
            reason, status = '', 'DENIED'
            db.execute('SAVEPOINT effect')
            try:
                if type(request) is not dict or set(request) != {'action', 'grant'}:
                    raise InvalidEnvelope('Request must contain only action and grant')
                action = validate_action(request['action'])
                state = self._state(db, action)
                condition = BindingCondition(action.action_hash, {**state, 'enabled': True})
                decision = Decision.from_dict(request['grant'])
                p = verify_decision(decision, self.public_key, action, condition, state)
                # The exact verified timestamp is recorded for independent replay.
                now = int(time.time())
                if not p['issued_at'] <= now < p['expires_at']:
                    raise AuthorizationDenied('Expired at effect boundary')
                if db.execute('SELECT 1 FROM revoked WHERE nonce=?', (p['nonce'],)).fetchone():
                    raise AuthorizationDenied('Revoked at execution')
                db.execute('INSERT INTO consumed VALUES (?)', (p['nonce'],))
                self._apply(db, action, VerifiedExecution(action.action_hash, p['nonce'], self.authority_hash))
                status, reason = 'EXECUTED', 'scope-and-current-condition-verified'
                db.execute('RELEASE effect')
            except (AuthorizationDenied, InvalidEnvelope, sqlite3.IntegrityError,
                    ValueError, KeyError, TypeError) as exc:
                db.execute('ROLLBACK TO effect')
                db.execute('RELEASE effect')
                reason = type(exc).__name__ + ': ' + str(exc)
            after = self._snapshot(db)
            receipt = self._event(db, {
                'kind': 'execution', 'time': now, 'request': request,
                'status': status, 'reason': reason,
                'before_hash': digest(before), 'after_hash': digest(after),
                'effect_count_before': len(before['effects']),
                'effect_count_after': len(after['effects']),
            })
            db.commit()
            return receipt

    def export(self):
        with self.db() as db:
            return {'schema': 'scdp.evidence/v1', 'public_key': self.public_key,
                    'authority_hash': self.authority_hash, 'policy': POLICY,
                    'events': [loads(r[0]) for r in db.execute('SELECT body FROM events ORDER BY seq')],
                    'final_state': self._snapshot(db)}
