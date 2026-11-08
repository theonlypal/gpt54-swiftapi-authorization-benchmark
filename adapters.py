"""Protected adapter contract. Only the trusted broker invokes this interface."""
from dataclasses import dataclass
from typing import Protocol
from vendor.swiftapi.brake.core import AuthorizationDenied


@dataclass(frozen=True)
class VerifiedExecution:
    """Broker-internal verified context, never reconstructed from client assertions."""
    action_hash: str
    nonce: str
    authority_hash: str


class TransactionalAdapter(Protocol):
    def apply(self, transaction, action, verified: VerifiedExecution) -> None: ...


class SimulatedFinancialAdapter:
    """Integer-unit transfers in the same transaction as grant consumption and receipt.

    No network, real account, fund, provider credential, settlement, or currency.
    Production external delivery requires the separately documented outbox contract.
    """
    def apply(self, transaction, action, verified):
        if verified is None or verified.action_hash != action.action_hash:
            raise AuthorizationDenied('Adapter requires broker-verified exact action')
        p = action.to_dict()['params']
        current = transaction.execute('SELECT cents FROM balances WHERE actor=? AND account=?',
                                      (action.actor, 'treasury')).fetchone()[0]
        if current < p['cents']:
            raise AuthorizationDenied('Insufficient simulated balance')
        transaction.execute("UPDATE balances SET cents=cents-? WHERE actor=? AND account='treasury'",
                            (p['cents'], action.actor))
        transaction.execute("UPDATE balances SET cents=cents+? WHERE actor=? AND account='vendor'",
                            (p['cents'], action.actor))
