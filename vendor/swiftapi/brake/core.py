"""Deterministic authorization. Trusted application code defines conditions and state.

Signatures authenticate statements, not the truth of arbitrary state. Execute only
through a registered broker with credentials outside an untrusted agent's reach.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Protocol

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from ..exceptions import SwiftAPIError


class BrakeError(SwiftAPIError):
    code = "BRAKE_ERROR"


class InvalidEnvelope(BrakeError):
    code = "INVALID_ENVELOPE"


class AuthorizationDenied(BrakeError):
    code = "GATE_BLOCK"


class ReplayError(AuthorizationDenied):
    code = "REPLAY"


def canonical(value: Any) -> bytes:
    """SwiftAPI JSON v1: UTF-8, sorted keys, no floats, safe integers, no coercion.

    This is a specified subset of JSON, not a claim of general RFC 8785 support.
    Unicode is preserved exactly (not normalized). Unsupported inputs fail closed.
    """

    def validate(v: Any, depth: int = 0) -> None:
        if depth > 64:
            raise InvalidEnvelope("JSON nesting exceeds 64")
        if v is None or type(v) in (bool, str):
            return
        if type(v) is int and abs(v) <= 9007199254740991:
            return
        if type(v) is list:
            for child in v:
                validate(child, depth + 1)
            return
        if type(v) is dict and all(type(k) is str for k in v):
            for child in v.values():
                validate(child, depth + 1)
            return
        raise InvalidEnvelope(
            "Expected JSON with string keys and safe integers; floats are unsupported"
        )

    validate(value)
    try:
        result = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (ValueError, UnicodeError, TypeError) as exc:
        raise InvalidEnvelope("Invalid UTF-8 JSON") from exc
    if len(result) > 2 * 1024 * 1024:
        raise InvalidEnvelope("Envelope exceeds 2 MiB")
    return result


def loads(data: Any) -> Any:
    def unique(pairs: Any) -> dict:
        out: dict = {}
        for k, v in pairs:
            if k in out:
                raise InvalidEnvelope("Duplicate JSON key")
            out[k] = v
        return out

    try:
        value = json.loads(data, object_pairs_hook=unique)
        canonical(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise InvalidEnvelope("Invalid JSON") from exc


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _hash(value: str) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def secure_dir(path: Path) -> Path:
    path = path.expanduser().absolute()
    # Resolve operator-chosen ancestors (macOS /tmp), reject a symlink leaf.
    if path.is_symlink():
        raise InvalidEnvelope("State directory must not be a symlink")
    path = path.resolve()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not path.is_dir() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise InvalidEnvelope("State directory must be owned by this user with mode 0700")
    return path


def write_exclusive(path: Path, value: Any) -> None:
    fd = os.open(
        str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(fd, "wb") as f:
        f.write(canonical(value) + b"\n")
        f.flush()
        os.fsync(f.fileno())


@dataclass(frozen=True)
class ActionEnvelope:
    capability: str
    params: Dict[str, Any]
    intent: str = ""
    actor: str = "local"
    _bytes: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not self.capability
            or type(self.capability) is not str
            or type(self.params) is not dict
            or type(self.intent) is not str
            or type(self.actor) is not str
        ):
            raise InvalidEnvelope("Invalid action fields")
        object.__setattr__(
            self,
            "_bytes",
            canonical(
                {
                    "capability": self.capability,
                    "params": self.params,
                    "intent": self.intent,
                    "actor": self.actor,
                }
            ),
        )
        object.__setattr__(self, "params", loads(canonical(self.params)))

    def to_dict(self) -> dict:
        return loads(self._bytes)

    @property
    def action_hash(self) -> str:
        return hashlib.sha256(self._bytes).hexdigest()


@dataclass(frozen=True)
class BindingCondition:
    """Exact action plus an independently supplied state object that must hold."""

    action_hash: str
    required_state: Dict[str, Any]
    name: str = "explicit-prerequisite"
    _bytes: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not _hash(self.action_hash)
            or type(self.required_state) is not dict
            or not self.required_state
            or not self.name
            or type(self.name) is not str
        ):
            raise InvalidEnvelope("Condition requires an exact action and nonempty required state")
        object.__setattr__(
            self,
            "_bytes",
            canonical(
                {
                    "action_hash": self.action_hash,
                    "required_state": self.required_state,
                    "name": self.name,
                }
            ),
        )
        object.__setattr__(self, "required_state", loads(canonical(self.required_state)))

    def to_dict(self) -> dict:
        return loads(self._bytes)

    @property
    def condition_hash(self) -> str:
        return hashlib.sha256(self._bytes).hexdigest()

    def evaluate(self, action: ActionEnvelope, state: dict) -> bool:
        return self.to_dict()["action_hash"] == action.action_hash and canonical(
            state
        ) == canonical(self.to_dict()["required_state"])


@dataclass(frozen=True)
class Decision:
    payload: dict
    signature: str
    _bytes: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_bytes", canonical(self.payload))
        object.__setattr__(self, "payload", loads(self._bytes))

    @property
    def allowed(self) -> bool:
        # Convenience only. Execution MUST independently verify the signed decision.
        return loads(self._bytes).get("allowed") is True

    def to_dict(self) -> dict:
        return {"payload": loads(self._bytes), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict) -> Decision:
        if type(value) is not dict or set(value) != {"payload", "signature"}:
            raise InvalidEnvelope("Invalid signed envelope")
        return cls(value["payload"], value["signature"])


DecisionReceipt = Decision


class ContinuationAuthority(Protocol):
    @property
    def public_key(self) -> str: ...
    def authorize(
        self,
        *,
        condition: Optional[BindingCondition],
        action: ActionEnvelope,
        state: dict,
        ttl: int = 300,
    ) -> Decision: ...


class LocalAuthority:
    def __init__(self, signing_key: Optional[SigningKey] = None):
        self._key = signing_key or SigningKey.generate()

    @property
    def public_key(self) -> str:
        return base64.b64encode(bytes(self._key.verify_key)).decode("ascii")

    @classmethod
    def load(cls, root: Path) -> LocalAuthority:
        root = secure_dir(root)
        path = root / "authority.key"
        if not path.exists():
            try:
                write_exclusive(
                    path, {"seed": base64.b64encode(bytes(SigningKey.generate())).decode("ascii")}
                )
            except FileExistsError:
                pass
        if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid():
            raise InvalidEnvelope("Unsafe signing key")
        return cls(SigningKey(base64.b64decode(loads(path.read_bytes())["seed"], validate=True)))

    def sign(self, payload: dict) -> Decision:
        signature = base64.b64encode(self._key.sign(canonical(payload)).signature).decode("ascii")
        return Decision(payload, signature)

    def authorize(
        self,
        *,
        condition: Optional[BindingCondition],
        action: ActionEnvelope,
        state: dict,
        ttl: int = 300,
    ) -> Decision:
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise InvalidEnvelope("TTL must be an integer from 1 to 3600 seconds")
        now = int(time.time())
        allowed = condition is not None and condition.evaluate(action, state)
        return self.sign(
            {
                "schema": "swiftapi.decision/v1",
                "issuer": self.public_key,
                "allowed": allowed,
                "action_hash": action.action_hash,
                "capability": action.capability,
                "condition_hash": condition.condition_hash if condition else None,
                "state_hash": digest(state),
                "nonce": secrets.token_hex(32),
                "issued_at": now,
                "expires_at": now + ttl,
                "reason": "prerequisite satisfied"
                if allowed
                else "prerequisite absent or unsatisfied",
            }
        )


def verify_receipt(receipt: Any, public_key: str) -> dict:
    """Verify with an independently trusted key, never a key supplied by the receipt."""
    try:
        d = receipt if isinstance(receipt, Decision) else Decision.from_dict(receipt)
        value = d.to_dict()
        VerifyKey(base64.b64decode(public_key, validate=True)).verify(
            canonical(value["payload"]), base64.b64decode(value["signature"], validate=True)
        )
        p = value["payload"]
        if p.get("issuer") != public_key or p.get("schema") not in {
            "swiftapi.decision/v1",
            "swiftapi.execution/v1",
        }:
            raise ValueError("schema or issuer")
        return p
    except (ValueError, KeyError, TypeError, BadSignatureError) as exc:
        raise AuthorizationDenied("Invalid signature, issuer, or receipt schema") from exc


def verify_decision(
    decision: Decision,
    public_key: str,
    action: ActionEnvelope,
    condition: BindingCondition,
    state: dict,
) -> dict:
    p = verify_receipt(decision, public_key)
    expected = {
        "schema",
        "issuer",
        "allowed",
        "action_hash",
        "capability",
        "condition_hash",
        "state_hash",
        "nonce",
        "issued_at",
        "expires_at",
        "reason",
    }
    if set(p) != expected or p["schema"] != "swiftapi.decision/v1" or p["allowed"] is not True:
        raise AuthorizationDenied("Authorization absent or denied")
    now = int(time.time())
    if (
        type(p["issued_at"]) is not int
        or type(p["expires_at"]) is not int
        or not p["issued_at"] <= now < p["expires_at"]
        or not 0 < p["expires_at"] - p["issued_at"] <= 3600
    ):
        raise AuthorizationDenied("Authorization expired, future dated, or invalid")
    if (
        not _hash(p["nonce"])
        or p["action_hash"] != action.action_hash
        or p["capability"] != action.capability
        or p["condition_hash"] != condition.condition_hash
        or p["state_hash"] != digest(state)
        or not condition.evaluate(action, state)
    ):
        raise AuthorizationDenied("Action, capability, condition, or state binding mismatch")
    return p


class ReplayLedger:
    """Durable atomic claim BEFORE execution. Failures consume the nonce too."""

    def __init__(self, root: Path):
        self.root = secure_dir(root)
        self.path = self.root / "replay.sqlite3"
        if self.path.is_symlink():
            raise InvalidEnvelope("Replay database may not be a symlink")
        fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        with sqlite3.connect(str(self.path), timeout=10) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS used (issuer TEXT NOT NULL, nonce TEXT NOT NULL, claimed INTEGER NOT NULL, PRIMARY KEY(issuer,nonce))"
            )

    def claim(self, issuer: str, nonce: str) -> None:
        try:
            with sqlite3.connect(str(self.path), timeout=10) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("INSERT INTO used VALUES (?,?,?)", (issuer, nonce, int(time.time())))
        except sqlite3.IntegrityError as exc:
            raise ReplayError("Authorization already consumed") from exc


class LocalGuard:
    """For trusted application callbacks; callback internals remain the caller's responsibility."""

    def __init__(self, authority: ContinuationAuthority, root: Path):
        self.authority = authority
        self.public_key = authority.public_key
        self.ledger = ReplayLedger(root)

    def run(
        self,
        function: Callable[[], Any],
        *,
        action: str,
        intent: str,
        condition: Optional[BindingCondition],
        params: Optional[dict] = None,
        state: Optional[dict] = None,
    ) -> Any:
        envelope = ActionEnvelope(action, params or {}, intent)
        current = loads(canonical(state or {}))
        decision = self.authority.authorize(condition=condition, action=envelope, state=current)
        if condition is None:
            raise AuthorizationDenied("Explicit condition required")
        p = verify_decision(decision, self.public_key, envelope, condition, current)
        write_exclusive(self.ledger.root / (p["nonce"] + ".json"), decision.to_dict())
        self.ledger.claim(p["issuer"], p["nonce"])
        return function()
