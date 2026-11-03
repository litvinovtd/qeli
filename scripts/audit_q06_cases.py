#!/usr/bin/env python3
"""Safe Q06 batches. Every child uses an exact artifact in private NET/mount/PID namespaces."""
import argparse,json,subprocess,sys
from pathlib import Path


def run_cases(description, scenarios):
    parser=argparse.ArgumentParser(description=description)
    parser.add_argument('--host',default='10.66.116.11')
    for name in ('qeli','sha256'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    scripts=Path(__file__).resolve().parent
    results=[]
    for scenario in scenarios:
        output=args.output/scenario
        command=[sys.executable,'-u','-X','utf8',str(scripts/'audit_web_auth_lab.py'),
                 '--host',args.host,'--audit','q06','--scenario',scenario,
                 '--fixture',str(scripts/'audit_web_transactions.py'),
                 '--qeli',args.qeli,'--sha256',args.sha256,'--output',str(output)]
        subprocess.run(command,check=True)
        result=json.loads((output/'results.json').read_text(encoding='utf-8'))
        if result['status']!='PASS' or not result['host_restored']:
            raise RuntimeError('Q06 child did not preserve the host: '+scenario)
        results.append({'scenario':scenario,'checks':result['case_result']['check_count'],
                        'artifact_sha256':result['artifact_sha256'],'host_restored':True})
    (args.output/'batch-result.json').write_text(json.dumps({'status':'PASS','results':results},indent=2)+'\n',encoding='utf-8')
    print('PASS Q06 batch: '+str(sum(x['checks'] for x in results))+' checks')
