"""Frozen reserved K4-shaped controls and refit ablations; no output retuning.

Run once after the shared package is frozen, through the computation-audit
runner. Censoring and unsuccessful recovery are saved outcomes, not errors.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.advanced_cli import json_safe_integers
from kryptos.validation_protocols import run_validation


def input_paths():
    paths=[p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'kryptos').glob('*.py'))]
    paths+=['research/benchmark_N.py','research/run_validation_N.py','research/N-validation-contract.json',
            'research/fixtures_N.json','research/structure_preflight_N.json','research/protocol_N.json',
            'examples/validate-k4-shaped.json','examples/validate-ablations.json',
            'tests/test_ablations.py','tests/test_validation_N.py','tests/test_validation_protocols.py',
            'tests/test_process_lifetime.py']
    for name in ('validate-k4-shaped','validate-ablations'):
        paths+=json.loads((ROOT/'examples'/f'{name}.json').read_text())['model_paths']
    return sorted(set(paths))


def hashes():
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in input_paths()}


def direct_encrypt(text,keys,stages):
    """Separate literal numeric implementation for this standard-alphabet bank."""
    next_key=iter(keys)
    for stage in stages:
        if stage['operation']=='gather':
            text=''.join(text[i] for i in stage['permutation'])
        else:
            key=next(next_key)
            text=''.join(chr(65+(ord(c)-65+ord(key[i%len(key)])-65)%26) for i,c in enumerate(text))
    return text


def structural_preflight():
    """Reproduce the recorded66 algebra-only checks; no scoring or truth text."""
    from kryptos.general_layers import solve_layers
    fixture=json.loads((ROOT/'research/fixtures_N.json').read_text())
    saved=json.loads((ROOT/'research/structure_preflight_N.json').read_text())
    known={i:'A' for i in fixture['mask_zero_based']}
    records=[]
    for width in (7,10):
        route=[i for col in range(width) for i in range(col,97,width)]
        for order in ('SST','STS','TSS'):
            options=[]
            for a,b in saved['pair_priority']:
                substitutions=iter([{'operation':'substitution','period':a},{'operation':'substitution','period':b}])
                stages=[next(substitutions) if s=='S' else {'operation':'gather','permutation':route} for s in order]
                solved=solve_layers('A'*97,known,stages,'standard')
                options.append({'periods':[a,b],'count':solved.distinct_plaintext_count,
                                'dimensions':[solved.dimensions_mod2,solved.dimensions_mod13]})
            records.append({'width':width,'order':order,'options':options})
    if records!=saved['records']:
        raise AssertionError('Algebra-only structural preflight changed')
    return {'verified':True,'models':66,'language_scoring':False}


def run():
    before=hashes()
    protocol=json.loads((ROOT/'research/protocol_N.json').read_text())
    if before['research/fixtures_N.json']!=protocol['fixture_sha256']:
        raise ValueError('Reserved fixture changed')
    for name,digest in protocol['requests'].items():
        if before[f'examples/{name}.json']!=digest:
            raise ValueError('Frozen request changed; do not retune this evidence record')
    structure=structural_preflight()
    request=json.loads((ROOT/'examples/validate-k4-shaped.json').read_text())
    controls=run_validation('validate-controls',request)
    bank={row['id']:row for row in request['model_bank']}
    checks=0
    for pair in controls['cases']:
        for kind in ('positive','null'):
            actual=direct_encrypt(pair[kind]['generating_plaintext'],pair['generating_keys'],bank[pair['generating_model_id']]['stages'])
            if actual!=pair[kind]['ciphertext']:
                raise AssertionError('Independent standard-alphabet encryption differs')
            checks+=1
    ablations=run_validation('validate-ablations',json.loads((ROOT/'examples/validate-ablations.json').read_text()))
    after=hashes()
    if before!=after:
        raise RuntimeError('An audited source/input changed')
    return {'schema':'kryptos.validation-N-audit.v1','protocol':protocol,'structural_preflight':structure,
            'controls':controls,'ablations':ablations,'independent_generator_checks':checks,
            'input_sha256_before':before,'input_sha256_after':after,
            'nonclaims':['No probability calibration, authenticated solution, or causal/historical stage necessity.',
                         'Declared widths and routes are ordinal hypotheses; no measured3D sculpture geometry.',
                         'Reserved synthetic multilingual prose is not representative or native-speaker-certified.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',action='store_true')
    parser.add_argument('--structure',action='store_true',help='recheck only66 all-zero algebra dimensions, no scores')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.inputs:
        print(json.dumps(input_paths(),indent=2));raise SystemExit(0)
    if args.structure:
        print(json.dumps(structural_preflight()));raise SystemExit(0)
    if args.output is None or args.output.exists():
        parser.error('--output requires a fresh file')
    result=run()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as handle:
        json.dump(json_safe_integers(result),handle,indent=2,allow_nan=False);handle.write('\n')
    print(json.dumps({'controls_complete':result['controls']['complete'],'controls_summary':result['controls']['summary'],
                      'ablations_complete':result['ablations']['complete'],'independent_generator_checks':result['independent_generator_checks']}))
