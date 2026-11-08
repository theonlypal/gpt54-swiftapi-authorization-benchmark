"""Human-designed bounded planner improvements, not autonomous AI-only RSI."""
from gate import digest


def lookup(strategy, records, queries, budget=None):
    units, results, cache = 0, [], {}
    index = {}
    if strategy != 'linear':
        for k, v in records:
            index[k] = v
            units += 1
    for q in queries:
        if strategy == 'linear':
            for k, v in records:
                units += 1
                if k == q:
                    results.append(v)
                    break
        elif strategy == 'index':
            units += 4  # fixed declared cost of protected catalog lookup
            results.append(index[q])
        elif strategy == 'memoized':
            units += 1  # fixed declared cache probe cost
            if q not in cache:
                units += 4
                cache[q] = index[q]
            results.append(cache[q])
        else:
            raise ValueError('Unknown strategy')
        if budget is not None and units > budget:
            return {'completed': False, 'work_units': units, 'answer_hash': None}
    return {'completed': True, 'work_units': units, 'answer_hash': digest(results),
            'values': results}


def improvement_study(gate, prefix='upgrade'):
    """Two fixed candidate searches; candidate catalog and cost model are public."""
    gate.initialize(prefix)
    authority_before = gate.authority_hash
    records = [(f'item-{k}', k * k) for k in range(100)]
    workloads = [([f'item-{k}' for k in range(100)], 'unique'),
                 (['item-99'] * 1000, 'repeated')]
    stages = []
    current = 'linear'
    for number, (queries, name) in enumerate(workloads, 1):
        # Stage 2 candidate retrieval goes through the installed planner, under a fixed budget.
        # Unique keys, with the target last, ensure linear and indexed costs are explicit.
        catalog = [(f'candidate-{k}', ['linear', 'index', 'memoized']) for k in range(100)]
        retrieval_queries = ['candidate-99'] * 1000
        retrieval = lookup(current, catalog, retrieval_queries, 5000) if number == 2 else None
        counterfactual = lookup('linear', catalog, retrieval_queries, 5000) if number == 2 else None
        if retrieval and not retrieval['completed']:
            stages.append({'stage': number, 'accepted': False, 'reason': 'catalog-budget'})
            break
        candidate_names = retrieval['values'][0] if number == 2 else ['linear', 'index', 'memoized']
        candidates = {s: lookup(s, records, queries) for s in candidate_names}
        winner = min(candidates, key=lambda s: (candidates[s]['work_units'], s))
        before, after = candidates[current], candidates[winner]
        action = {'capability': 'agent.install', 'params': {'strategy': winner},
                  'actor': prefix, 'intent': f'planner improvement {number}'}
        improvement_valid = (before['answer_hash'] == after['answer_hash']
                             and 4 * after['work_units'] <= 3 * before['work_units'])
        if not improvement_valid:
            stages.append({'stage': number, 'accepted': False, 'reason': 'validation-failed'})
            break
        grant = gate.authorize(action)
        receipt = gate.execute({'action': action, 'grant': grant})
        accepted = receipt['payload']['status'] == 'EXECUTED'
        stages.append({'stage': number, 'workload': name, 'prior': current,
                       'selected': winner, 'before': before, 'after': after,
                       'candidates': candidates, 'retrieval': retrieval,
                       'counterfactual_prior_linear': counterfactual,
                       'receipt_seq': receipt['payload']['seq'], 'accepted': accepted})
        current = next(x['strategy'] for x in gate.snapshot()['agents'] if x['actor'] == prefix)
    # An attempted privilege change is submitted as an action, not silently discarded.
    forbidden = {'capability': 'agent.install', 'params': {'strategy': 'memoized', 'authority_override': True},
                 'actor': prefix, 'intent': 'alter governing authority'}
    attempt = gate.execute({'action': forbidden, 'grant': None})
    return {'schema': 'scdp.improvements/v1', 'autonomous_ai_only_rsi_tested': False,
            'design': 'human-designed deterministic finite candidate search',
            'cost_model': {'linear_compare': 1, 'index_build_entry': 1, 'catalog_lookup': 4, 'cache_probe': 1},
            'stages': stages, 'authority_hash_before': authority_before,
            'authority_hash_after': gate.authority_hash,
            'authority_mutation_status': attempt['payload']['status'],
            'contribution_test': bool(len(stages) == 2 and stages[1].get('retrieval', {}).get('completed')
                                     and not stages[1].get('counterfactual_prior_linear', {}).get('completed'))}
