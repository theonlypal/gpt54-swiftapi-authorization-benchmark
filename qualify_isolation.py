"""macOS sandboxed client qualification; no unsandboxed fallback."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from gate import Gate
from cases import action_for
from server import make_server
from verify_evidence import verify

PROFILE = '''(version 1)
(deny default)
(allow process-exec (literal (param "EXEC")))
(allow sysctl-read)
(allow file-read-metadata)
(allow file-read-data file-map-executable
 (literal "/") (subpath "/System") (subpath "/usr/lib")
 (subpath (param "PYTHON")) (subpath (param "CODE"))
 (literal "/dev/urandom") (literal "/dev/random"))
(allow network-outbound (remote ip (param "BROKER")))'''
CHILD = r'''
import json,socket,sys
from pathlib import Path
from urllib.request import Request,urlopen
d=json.load(sys.stdin); root=Path(d['root']); checks={}
for name,fn in {
 'read_signing_key':lambda:(root/'authority.key').read_bytes(),
 'read_database':lambda:(root/'state.sqlite3').read_bytes(),
 'write_database':lambda:(root/'state.sqlite3').open('ab'),
 'write_grant':lambda:(root/'forged-grant').write_text('approved'),
 'write_governing_code':lambda:Path(d['code']).open('ab'),
 'alternate_network':lambda:socket.create_connection(('127.0.0.1',1),timeout=1),
}.items():
 try:
  fn(); checks[name]='ESCAPED'
 except PermissionError: checks[name]='BLOCKED_BY_OS'
 except Exception as exc: checks[name]='UNPROVEN:'+type(exc).__name__
receipts=[]
for grant in [None,d['grant'],d['grant']]:
 req=Request(d['url']+'/execute',data=json.dumps({'action':d['action'],'grant':grant}).encode(),
             headers={'Content-Type':'application/json'})
 with urlopen(req,timeout=5) as f: receipts.append(json.load(f))
print(json.dumps({'checks':checks,'receipts':receipts}))
'''

def qualify(output):
    if sys.platform != 'darwin' or not Path('/usr/bin/sandbox-exec').exists():
        raise SystemExit('macOS sandbox unavailable; no fallback')
    output=Path(output)
    if output.exists(): raise SystemExit('New output file required')
    root=Path(tempfile.mkdtemp(prefix='scdp-isolated-')).resolve()
    g=Gate(root); g.initialize('isolated')
    a=action_for('finance','isolated'); grant=g.authorize(a)
    s=make_server(g); t=threading.Thread(target=s.serve_forever,daemon=True); t.start()
    try:
        cmd=['/usr/bin/sandbox-exec','-D','EXEC='+str(Path(sys.executable).resolve()),
             '-D','PYTHON='+str(Path(sys.base_prefix).resolve()),
             '-D','CODE='+str(Path(__file__).resolve().parent),
             '-D','BROKER=localhost:'+str(s.server_port),'-p',PROFILE,sys.executable,'-I','-B','-c',CHILD]
        payload={'root':str(root),'code':str(Path(__file__).parent/'gate.py'),
                 'url':f'http://127.0.0.1:{s.server_port}','action':a,'grant':grant}
        p=subprocess.run(cmd,input=json.dumps(payload),capture_output=True,text=True,timeout=30,
                         env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'},close_fds=True)
        report={'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'profile':PROFILE,
                'scope':'sandboxed child only; IDE agents and trusted host are not sandboxed',
                'sandbox_exec_deprecated':True,'evidence':g.export()}
        if p.returncode==0:
            child=json.loads(p.stdout)
            report['checks']=child['checks']
            report['statuses']=[r['payload']['status'] for r in child['receipts']]
            report['verification']=verify(g.export(),g.public_key,g.authority_hash)
            report['passed']=(all(v=='BLOCKED_BY_OS' for v in child['checks'].values())
                              and report['statuses']==['DENIED','EXECUTED','DENIED']
                              and len(g.snapshot()['effects'])==1)
        else: report['passed']=False
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k in ['passed','checks','statuses','returncode']},indent=2))
        if not report['passed']: raise SystemExit('Isolation qualification failed; no fallback')
    finally:
        s.shutdown();s.server_close();t.join()

if __name__=='__main__': qualify(sys.argv[1])
