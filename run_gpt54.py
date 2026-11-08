"""One-shot direct Responses API collection with durable pre-request reservations."""
import argparse
from datetime import datetime,timezone
from decimal import Decimal
import hashlib,json,os,subprocess,time
from pathlib import Path
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError
from study import MODEL,ENDPOINT,encode,parse_response,sha

ROOT=Path(__file__).resolve().parent
RESERVE=Decimal('0.05768')  # 20,000 input + 512 output at standard rates.

def utc(): return datetime.now(timezone.utc).isoformat()
def save(path,value):
    with path.open('xb') as f:
        f.write(encode(value)+b'\n'); f.flush(); os.fsync(f.fileno())

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise RuntimeError('Redirect denied')

def check_freeze():
    freeze=(ROOT/'FREEZE_COMMIT.txt').read_text().strip()
    for line in (ROOT/'FREEZE_SHA256SUMS').read_text().splitlines():
        h,name=line.split('  ',1)
        if sha((ROOT/name).read_bytes())!=h: raise RuntimeError('Frozen file changed: '+name)
    subprocess.run(['git','merge-base','--is-ancestor',freeze,'HEAD'],cwd=ROOT,check=True)
    return freeze

def amount(usage):
    i=usage['input_tokens'];o=usage['output_tokens'];c=usage.get('input_tokens_details',{}).get('cached_tokens',0)
    if any(type(x)!=int or x<0 for x in [i,o,c]) or c>i: raise ValueError('Invalid usage')
    return (Decimal(i-c)*Decimal('2.50')+Decimal(c)*Decimal('0.25')+Decimal(o)*Decimal('15.00'))/1000000

def collect(mode):
    freeze=check_freeze(); key=os.environ.get('OPENAI_API_KEY')
    if not key: raise RuntimeError('OPENAI_API_KEY is not set')
    raw=ROOT/'raw';raw.mkdir(exist_ok=True)
    if mode=='primary':
        pre=json.loads((raw/'preflight'/'record.json').read_bytes())
        if not pre['compatible']: raise RuntimeError('Preflight did not qualify')
        rows=json.loads((ROOT/'SCHEDULE.json').read_bytes())
    else:
        req={'model':MODEL,'input':'Return the single word READY.','reasoning':{'effort':'none'},'max_output_tokens':512,
             'store':False,'stream':False,'service_tier':'default'}
        rows=[{'slot':'preflight','request':req}]
    opener=build_opener(ProxyHandler({}),NoRedirect())
    for row in rows:
        dest=raw/row['slot']
        if dest.exists(): raise RuntimeError('Slot already reserved; no inference retry: '+row['slot'])
        charges=[]
        for old in raw.iterdir():
            if not old.is_dir(): continue
            if not (old/'record.json').exists(): raise RuntimeError('Unresolved prior charge; stopping')
            m=json.loads((old/'record.json').read_bytes())
            if m['cost_usd'] is None: raise RuntimeError('Unknown prior charge; stopping')
            charges.append(Decimal(m['cost_usd']))
        spent=sum(charges,Decimal(0))
        if spent+RESERVE>Decimal('20'): raise RuntimeError('Budget ceiling before request')
        data=encode(row['request'])
        if len(data)>10000: raise RuntimeError('Input exceeds frozen conservative bound')
        dest.mkdir();(dest/'request.json').write_bytes(data)
        save(dest/'reservation.json',{'slot':row['slot'],'at':utc(),'freeze_commit':freeze,'reserved_usd':str(RESERVE),
                                     'settled_before_usd':str(spent),'request_sha256':sha(data),'endpoint':ENDPOINT})
        start=utc(); code=None; headers={};body=b'';error=None
        req=Request(ENDPOINT,data=data,headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
        try:
            with opener.open(req,timeout=120) as response:
                code=response.status;body=response.read();headers=dict(response.headers)
        except HTTPError as exc:
            code=exc.code;body=exc.read();headers=dict(exc.headers)
        except Exception as exc:
            error=type(exc).__name__  # no credentials or local traceback
        (dest/'response.bin').write_bytes(body)
        allowed={'x-request-id','date','content-type','openai-version','openai-processing-ms','retry-after'}
        save(dest/'headers.json',{k.lower():v for k,v in headers.items() if k.lower() in allowed})
        parsed={}
        try: parsed=json.loads(body)
        except Exception: pass
        usage=parsed.get('usage');cost=None
        if usage is not None:
            try: cost=str(amount(usage))
            except Exception: pass
        # Known rejected requests have no generation charge; uncertain transport stays reserved.
        if code in [400,401,403,404,429] and not usage: cost='0'
        compatible=(code==200 and parsed.get('model')==MODEL and parsed.get('status')=='completed'
                    and parsed.get('service_tier') in [None,'default'] and usage is not None
                    and usage.get('input_tokens',20001)<=20000 and usage.get('output_tokens',513)<=512)
        record={'slot':row['slot'],'start_utc':start,'end_utc':utc(),'http_status':code,'transport_error':error,
                'request_sha256':sha(data),'response_sha256':sha(body),'model':parsed.get('model'),
                'response_id':parsed.get('id'),'created_at':parsed.get('created_at'),'status':parsed.get('status'),
                'usage':usage,'cost_usd':cost,'compatible':compatible,'error':parsed.get('error')}
        if mode=='primary': record['proposal']=parse_response(parsed,row)
        save(dest/'record.json',record)
        print(json.dumps({'slot':row['slot'],'http':code,'compatible':compatible,'cost_usd':cost}),flush=True)
        if cost is None or (code==200 and not compatible and parsed.get('status')!='incomplete'):
            raise RuntimeError('Unknown cost or incompatible returned model/profile; receipt retained')
        if code in [401,403,429] or error: raise RuntimeError('Access, quota, or transport blocker; receipt retained')
    print('COLLECTION COMPLETE '+mode,flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['preflight','primary']);collect(p.parse_args().mode)
