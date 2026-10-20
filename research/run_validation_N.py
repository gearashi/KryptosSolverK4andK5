"""Own the complete process tree while running the frozen phase-N validation.

Prepare-only writes an execution contract without running any benchmark. A full
run requires a fresh label, uses unchanged scientific bounds, and validates the
runner's manifest. CPU-only; no external service or corpus download is used.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.process_lifetime import launch_owned
from research.benchmark_N import input_paths


def owned_check(argv, env, timeout):
    with tempfile.TemporaryFile(mode='w+b',dir=ROOT/'runtime/cache/tmp') as log:
        process=launch_owned(argv,cwd=str(ROOT),env=env,stdout=log,stderr=log)
        try:
            code=process.wait(timeout=timeout)
        finally:
            process.close()  # Windows JobObject / POSIX process group owns descendants.
            log.seek(0)
            output=log.read(65537)
            print(output[:65536].decode('utf-8',errors='replace'),end='',flush=True)
            if len(output)>65536:
                print('\nWrapper log truncated at65536bytes; canonical child logs remain in the audit directory.')
        if code:
            raise subprocess.CalledProcessError(code,argv)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit-skill',type=Path,required=True,
                        help='Installed computation-audit skill directory')
    parser.add_argument('--label',default='release-N-001')
    parser.add_argument('--prepare-only',action='store_true')
    args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*',args.label):
        parser.error('Use a simple alphanumeric/hyphen label')
    skill=args.audit_skill.resolve()
    for name in ('run_experiment.py','validate_manifest.py'):
        if not (skill/'scripts'/name).is_file():
            parser.error('The supplied skill directory lacks its runner or validator')
    output=Path('research/runs')/args.label/'validation'
    if (ROOT/output).exists():
        raise FileExistsError('Use a fresh audit label; prior results are preserved')
    contract=json.loads((ROOT/'research/N-validation-contract.json').read_text(encoding='utf-8'))
    paths=input_paths()
    contract['execution_artifacts']=paths
    contract['mathematics']['inputs']=paths
    contract['software']=[{'name':'Python','version':sys.version.split()[0]}]
    contract_path=ROOT/'research'/f'{args.label}-validation-contract.json'
    if contract_path.exists():
        # Permit a prepare-only handoff only if the exact contract is unchanged.
        if json.loads(contract_path.read_text(encoding='utf-8'))!=contract:
            raise ValueError('Prepared contract changed; choose a fresh audit label')
    else:
        with contract_path.open('x',encoding='utf-8') as handle:
            json.dump(contract,handle,indent=2,allow_nan=False);handle.write('\n')
    if args.prepare_only:
        print(json.dumps({'contract':str(contract_path),'input_count':len(paths),'benchmark_started':False}))
        return
    env=os.environ.copy()
    for name,part in (('TEMP','tmp'),('TMP','tmp'),('CUPY_CACHE_DIR','cupy')):
        folder=ROOT/'runtime/cache'/part
        folder.mkdir(parents=True,exist_ok=True)
        env[name]=str(folder)
    result=output/'result.json'
    outer=contract['mathematics']['bounds']['outer_seconds']
    command=[sys.executable,str(skill/'scripts/run_experiment.py'),'--root',str(ROOT),
             '--contract',str(contract_path),'--output',output.as_posix(),'--result',result.as_posix(),
             '--timeout',str(outer),'--max-output-bytes','1048576','--max-threads','1']
    for path in paths:
        command+=['--input',path]
    command+=['--',sys.executable,'-B','research/benchmark_N.py','--output',result.as_posix()]
    owned_check(command,env,outer+20)
    owned_check([sys.executable,str(skill/'scripts/validate_manifest.py'),str(ROOT/output/'manifest.json'),
                 '--root',str(ROOT)],env,30)


if __name__=='__main__':main()
