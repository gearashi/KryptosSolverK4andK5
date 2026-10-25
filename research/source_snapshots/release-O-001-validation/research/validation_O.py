"""Frozen O competing-family/null protocol and bounded ordinal-path controls.

Use --inputs for the manifest closure, --preflight for structural/mechanical
checks without scoring reserved prose, or --output with a fresh result path.
All ranks and unsuccessful/censored outcomes are retained without tuning.
"""
from itertools import product
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from kryptos.advanced_cli import json_safe_integers
from kryptos.family_identity import canonical_coset
from kryptos.general_layers import solve_layers
from kryptos.grid_paths import generate_path_routes,path_route,replay_path
from kryptos.sculpture import section_cells,PACKAGED_LAYOUT_SHA256
from kryptos.validation_protocols import run_validation


def input_paths():
    paths=[p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'kryptos').glob('*.py'))]
    paths+=['research/validation_O.py','research/fixtures_O.json','research/protocol_O.json',
            'research/grid_paths_O_protocol.json','research/sculpture_layout.json','examples/validate-campaign-null.json',
            'tests/test_validation_O.py','tests/test_grid_paths.py','tests/test_validation_protocols.py','tests/test_hypotheses.py']
    request=json.loads((ROOT/'examples/validate-campaign-null.json').read_text())
    return sorted(set(paths+request['model_paths']))


def hashes():
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in input_paths()}


def literal_encrypt(text,keys,stages):
    """Separate numeric loop for these explicitly standard-alphabet fixtures."""
    keys=iter(keys)
    for stage in stages:
        if stage['operation']=='gather':
            text=''.join(text[i] for i in stage['permutation'])
        else:
            key=next(keys)
            text=''.join(chr(65+(ord(c)-65+ord(key[i%len(key)])-65)%26) for i,c in enumerate(text))
    return text


def structural_controls():
    request=json.loads((ROOT/'examples/validate-campaign-null.json').read_text())
    known={i:'A' for i in request['crib_positions']}
    counts=[];identities=[]
    for row in request['model_bank']:
        s=solve_layers('A'*97,known,row['stages'],'standard')
        counts.append(s.distinct_plaintext_count)
        identities.append([canonical_coset(f.plaintext_base,f.plaintext_columns,f.modulus) for f in (s.field2,s.field13)])
    distinct=len({json.dumps(i,sort_keys=True) for i in identities})
    if counts!=[26,676,26] or distinct!=3:
        raise AssertionError('Fixed zero-text family design differs')
    return {'family_counts':counts,'distinct_linear_plaintext_families':distinct,'scoring_performed':False,
            'scope':'The24 masked originals occupy24 distinct key slots in every declared model; every crib RHS is feasible. Differing free-direction spans/cardinalities guarantee inequivalent affine sets independently of scoring.'}


def grid_controls():
    protocol=json.loads((ROOT/'research/grid_paths_O_protocol.json').read_text())
    cells=[(c.row,c.column) for c in section_cells('K4')]
    generated=generate_path_routes(cells,protocol['settings'])
    if any(generated[k]!=v for k,v in protocol['expected_counts'].items()):
        raise AssertionError('Fixed path population changed')
    generating=path_route(cells,protocol['generator'])
    if not generating['complete']:
        raise AssertionError('Declared mechanical generator is not bijective')
    text=protocol['control_plaintext']; key=protocol['control_key']
    def stages(route):
        return [{'operation':'gather','permutation':route},{'operation':'substitution','period':len(key)}]
    cipher=literal_encrypt(text,[key],stages(generating['permutation']))
    known=dict(enumerate(text))
    calls={'raw':0,'deduplicated':0};work={'raw':0,'deduplicated':0};replays=0
    def check(route,mode):
        nonlocal replays
        s=solve_layers(cipher,known,stages(route),'standard')
        calls[mode]+=1;work[mode]+=s.work
        # Independent full-plaintext Vigenere key consistency after the gather.
        slots={}
        for j,i in enumerate(route):
            value=(ord(cipher[j])-ord(text[i]))%26
            slot=j%len(key)
            if slot in slots and slots[slot]!=value:
                expected=False;break
            slots[slot]=value
        else:expected=True
        if s.feasible!=expected:
            raise AssertionError('Independent direct key constraints disagree')
        words=[]
        if s.feasible:
            if s.distinct_plaintext_count!=1:raise AssertionError('Full supplied plaintext must leave one plaintext')
            candidate=s.candidate()
            if candidate['plaintext']!=text or literal_encrypt(text,candidate['keys'],stages(route))!=cipher:
                raise AssertionError('Mechanical known control literal replay differs')
            words=[candidate['plaintext']];replays+=1
        return {'feasible':s.feasible,'plaintexts':words,'algebra_work':s.work}
    raw_results={};raw_records=[]
    for route in generated['routes']:
        for parameters in route['parameter_aliases']:
            replay_path(cells,parameters,route['permutation'])
            record=check(route['permutation'],'raw')
            raw_records.append({'parameters':parameters,**record})
            raw_results[tuple(route['permutation'])]=record
    unique_records=[]
    for route in generated['routes']:
        record=check(route['permutation'],'deduplicated')
        if record!=raw_results[tuple(route['permutation'])]:
            raise AssertionError('Parameter deduplication changed a cipher classification')
        unique_records.append({'id':route['id'],**record})
    if calls['raw']<=calls['deduplicated'] or work['raw']<=work['deduplicated']:
        raise AssertionError('Declared duplicate control did not reduce solver calls and counted algebra')
    return {'protocol':protocol,'normalized_layout_sha256':PACKAGED_LAYOUT_SHA256,'generated':generated,
            'ciphertext':cipher,'solver_calls':calls,'counted_algebra_work':work,
            'raw_records':raw_records,'unique_records':unique_records,'known_candidate_replays':replays,
            'steps_avoided':{'nonbijective_walks_rejected_before_cipher':generated['nonbijective_hypotheses'],
                             'duplicate_cipher_solver_calls':calls['raw']-calls['deduplicated']},
            'interpretation':'Fewer cipher constraint calls on this finite parameter set, preserving every distinct route and exact answer. No claim of fewer steps for every grid or of a recovered sculpture path.'}


def run():
    before=hashes()
    protocol=json.loads((ROOT/'research/protocol_O.json').read_text())
    for path,key in [('research/fixtures_O.json','fixture_sha256'),('examples/validate-campaign-null.json','request_sha256')]:
        if before[path]!=protocol[key]:raise ValueError('Frozen phase O input changed; do not retune outcomes')
    structure=structural_controls()
    grid=grid_controls()
    request=json.loads((ROOT/'examples/validate-campaign-null.json').read_text())
    controls=run_validation('validate-controls',request)
    bank={r['id']:r for r in request['model_bank']};checks=0
    for case in controls['cases']:
        for value in [case['positive']]+case['null_replicates']:
            actual=literal_encrypt(value['generating_plaintext'],case['generating_keys'],bank[case['generating_model_id']]['stages'])
            if actual!=value['ciphertext']:raise AssertionError('Independent generated-input replay differs')
            checks+=1
    after=hashes()
    if before!=after:raise RuntimeError('An audited source or input changed')
    return {'schema':'kryptos.validation-O-audit.v1','protocol':protocol,'structure':structure,'grid_paths':grid,
            'controls':controls,'independent_generator_checks':checks,
            'input_sha256_before':before,'input_sha256_after':after,
            'nonclaims':['Truth recovery/rank is an observed outcome, not a required success threshold.',
                'The finite engineered family bank and conditional shuffles do not estimate real-world authenticity.',
                'No K4/K5 decipherment, arbitrary path search, or measured3D geometry claim.']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',action='store_true')
    parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.inputs:print(json.dumps(input_paths(),indent=2));raise SystemExit(0)
    if args.preflight:
        grid=grid_controls()
        print(json.dumps({'structure':structural_controls(),'grid_calls':grid['solver_calls'],'grid_algebra':grid['counted_algebra_work'],'scoring_performed':False}));raise SystemExit(0)
    if args.output is None or args.output.exists():parser.error('--output requires a fresh file')
    result=run();args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(json_safe_integers(result),stream,indent=2,allow_nan=False);stream.write('\n')
    print(json.dumps({'complete':result['controls']['complete'],'family_coverage':result['controls']['family_coverage'],
                      'calibration':result['controls']['calibration'],'grid_calls':result['grid_paths']['solver_calls'],
                      'independent_generator_checks':result['independent_generator_checks']}))
