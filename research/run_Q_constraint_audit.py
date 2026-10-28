"""Run the immutable Q constraint audit with owned Windows descendants."""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.process_lifetime import launch_owned


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode('utf-8')


def owned_run(argv, environment, timeout):
    directory=ROOT/'runtime/cache/tmp'
    directory.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryFile(mode='w+b',dir=directory) as log:
        process=launch_owned(argv,cwd=ROOT,env=environment,stdout=log,stderr=log)
        try:
            code=process.wait(timeout=timeout)
        finally:
            process.close()
            log.seek(0)
            data=log.read(65537)
            print(data[:65536].decode('utf-8',errors='replace'),end='',flush=True)
            if len(data)>65536:
                print('\nWrapper output truncated; canonical logs remain in the audit directory.')
    return code


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--audit-skill',type=Path,required=True)
    parser.add_argument('--label',default='release-Q-001')
    args=parser.parse_args()
    import re
    if not re.fullmatch(r'[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*',args.label):
        raise ValueError('Label must be alphanumeric/hyphen')
    skill=args.audit_skill.resolve()
    for name in ('run_experiment.py','validate_manifest.py'):
        if not (skill/'scripts'/name).is_file():
            raise ValueError('Installed computation audit runner unavailable')
    output=Path('research/runs')/args.label/'constraints'
    snapshot=ROOT/'research/source_snapshots'/f'{args.label}-constraints'
    contract_path=ROOT/'research/contracts'/f'{args.label}-constraints.json'
    if (ROOT/output).exists() or snapshot.exists() or contract_path.exists():
        raise FileExistsError('Preserve previous audit/preparation records; use a fresh label')
    original_contract=ROOT/'research/contracts/Q-constraints.json'
    contract=deepcopy(json.loads(original_contract.read_text(encoding='utf-8')))
    paths=sorted(set(contract['execution_artifacts']) |
        {p.relative_to(ROOT).as_posix() for p in (ROOT/'kryptos').rglob('*.py')} |
        {'research/run_Q_constraint_audit.py','research/contracts/Q-constraints.json'})
    # The original protocol remains immutable history. This final contract adds
    # the peer-review boundary regressions and pins the current source closure.
    contract['execution_artifacts']=paths
    contract['mathematics']['bounds']['unit_tests']=34
    contract['mathematics']['bounds']['outer_seconds']=120
    contract['mathematics']['assertion_tested']+=' Public affine helper boundaries reject invalid fields/domains and malformed vectors.'
    contract['mathematics']['inputs'].append('Peer-review malformed-affine-domain matrix and zero-variable positive control')
    originals={}
    for name in paths:
        path=(ROOT/name).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
            raise ValueError(f'Invalid declared source input: {name}')
        originals[name]=path.read_bytes()
    hashes={name:digest(data) for name,data in originals.items()}
    contract_bytes=encoded(contract)
    snapshot.mkdir(parents=True)
    for name,data in originals.items():
        path=snapshot/name
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
    (snapshot/'_audit').mkdir()
    with (snapshot/'_audit/contract.json').open('xb') as stream:
        stream.write(contract_bytes)
    contract_path.parent.mkdir(parents=True,exist_ok=True)
    with contract_path.open('xb') as stream:
        stream.write(contract_bytes)
    preparation={'schema':'kryptos.Q-constraint-preparation.v1','input_hashes':hashes,'contract_sha256':digest(contract_bytes),
        'audit_helpers':{name:digest((skill/'scripts'/name).read_bytes()) for name in ('run_experiment.py','validate_manifest.py')},
        'interpreter':str(Path(sys.executable).resolve()),'output':output.as_posix()}
    with (snapshot/'_audit/preparation.json').open('xb') as stream:
        stream.write(encoded(preparation))
    environment=os.environ.copy()
    for name in ('TEMP','TMP'):
        environment[name]=str(ROOT/'runtime/cache/tmp')
    result=output/'result.json'
    argv=[sys.executable,str(skill/'scripts/run_experiment.py'),'--root',str(ROOT),'--contract',str(contract_path),
        '--output',output.as_posix(),'--result',result.as_posix(),'--timeout','120','--max-output-bytes','4194304','--max-threads','1']
    for name in paths:
        argv+=['--input',name]
    argv+=['--',sys.executable,'-B','research/audit_Q_constraints.py','--output',result.as_posix()]
    code=owned_run(argv,environment,150)
    manifest_path=ROOT/output/'manifest.json'
    if not manifest_path.is_file():
        raise RuntimeError('Audit runner left no manifest; preserve incomplete outputs')
    validated=owned_run([sys.executable,str(skill/'scripts/validate_manifest.py'),str(manifest_path),'--root',str(ROOT)],environment,30)
    if validated:
        raise subprocess.CalledProcessError(validated,'validate_manifest.py')
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    observed={row['path']:row['sha256'] for row in manifest['input_artifacts']}
    if observed!=hashes or any(row['sha256_after']!=row['sha256'] for row in manifest['input_artifacts']):
        raise AssertionError('Observed inputs changed or differ from the snapshot')
    for name,expected in hashes.items():
        if digest((ROOT/name).read_bytes())!=expected or digest((snapshot/name).read_bytes())!=expected:
            raise AssertionError(f'Current/snapshot input changed: {name}')
    closure={'schema':'kryptos.Q-constraint-closure.v1','status':manifest['run']['status'],'input_count':len(paths),
        'current_and_snapshot_hashes_match':True,'snapshot':snapshot.relative_to(ROOT).as_posix(),
        'execution_files':{path.relative_to(ROOT).as_posix():digest(path.read_bytes()) for path in
            (manifest_path,ROOT/output/'stdout.txt',ROOT/output/'stderr.txt',ROOT/result) if path.is_file()}}
    with (ROOT/output/'snapshot-verification.json').open('xb') as stream:
        stream.write(encoded(closure))
    print(json.dumps(closure,indent=2))
    if code:
        raise subprocess.CalledProcessError(code,argv)
    checked=json.loads((ROOT/result).read_text(encoding='utf-8'))
    if manifest['run']['status']!='completed' or checked['status']!='completed' or checked['tests']['run']!=34:
        raise AssertionError('Finite audit did not satisfy its final contract')


if __name__=='__main__':
    main()
