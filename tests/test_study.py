import json
import pytest
from study import schedule,parse_response,MODEL
from enforce_gpt54 import run_environment,ATTACKS
from verify_evidence import verify
from verify_study import proposal

def fixture(row):
    a={'actor':row['slot'],'capability':row['capability'],'params':row['user']['allowed_parameters'],'intent':'scoped local task'}
    b={'model':MODEL,'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':json.dumps({'action':a})}]}]}
    return a,b

def test_schedule():
    rows=schedule();assert len(rows)==80 and len({r['slot'] for r in rows})==80
    assert all(sum(r['domain']==d for r in rows)==20 for d in ['software','browser','finance','agent'])
    assert all(r['request']['model']==MODEL for r in rows)

@pytest.mark.parametrize('mutation',['none','refusal','malformed','model','scope','empty','provider_refusal','duplicate'])
def test_independent_parser(mutation):
    row=schedule()[0];a,b=fixture(row)
    t=b['output'][0]['content'][0]
    if mutation=='refusal': t['text']='{"refusal":"denied"}'
    elif mutation=='malformed': t['text']='```json\n{}\n```'
    elif mutation=='model': b['model']='other'
    elif mutation=='scope': a['params']={**a['params'],'name':'different'};t['text']=json.dumps({'action':a})
    elif mutation=='empty': t['text']=''
    elif mutation=='provider_refusal': b['output'][0]['content']=[{'type':'refusal','refusal':'no'}]
    elif mutation=='duplicate': t['text']='{"refusal":"no","refusal":"yes"}'
    parsed=parse_response(b,row)
    assert proposal(b,row)==(parsed['status'],parsed['action'],parsed['in_scope'])

@pytest.mark.parametrize('scenario',['satisfied','unsatisfied']+ATTACKS)
def test_real_isolated_enforcement(scenario):
    row=next(r for r in schedule() if r['domain']=='finance');a,_=fixture(row)
    e=run_environment(a,scenario)
    assert e['isolation_passed']
    assert e['expected_effects']==e['observed_effects']
    assert verify(e['evidence'],e['evidence']['public_key'],e['evidence']['authority_hash'])['verified']
    if scenario=='interrupted_retry':
        assert e['interruption']['exit_code']==91
        assert e['interruption']['post_crash_state']==e['before_state']
