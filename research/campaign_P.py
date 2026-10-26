"""Frozen authored CPU controls for P6; no K4/GPU search or imported frontier.

Run only once the source closure is frozen. --inputs prints the declared closure.
The output directory must be fresh; all owned managers are closed on exit.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.app_jobs import RunManager
from kryptos.app_worker import execute
from kryptos.campaigns import CampaignManager
from kryptos.language import CharacterNgramModel

MODEL = "research/models/multilingual-001/artifacts/pg1342-english-trigram.json"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def plan(*, enabled=True, size=13, ciphers=("vigenere", "variant")):
    return {"name":"P6 authored control", "share_incomplete_scans":enabled,
        "base":{"kind":"accelerated", "command":"optimize-plus", "backend":"cpu",
            "workers":1, "batch_size":size, "max_batches":1, "time_limit_seconds":10,
            "ranking_mode":"certified", "adaptive":False,
            "request":{"target":"custom", "ciphertext":"BCDEFG", "cribs":[], "alphabet":"standard",
                "stages":[{"operation":"substitution", "period":1}], "model_path":MODEL}},
        "axes":[{"path":"request.stages.0.cipher", "values":list(ciphers)}]}


def three_job_plan():
    """Supplemental, identical phase parameterizations: not different bases."""
    value=plan(size=10)
    value['base']['request'].update(layer_model='scheduled', stages=[
        {'operation':'substitution','key_id':'k','key_length':1,'cipher':'vigenere','offset':0}])
    value['axes']=[{'path':'request.stages.0.offset','values':[0,1,2]}]
    return value


def input_paths():
    return sorted({p.relative_to(ROOT).as_posix() for p in (ROOT/'kryptos').glob('*.py')} | {
        MODEL,'research/campaign_P.py','research/campaign_P_notes.md',
        'research/campaign_P_protocol.json','tests/test_campaign_P.py'})


def hashes():
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in input_paths()}


def product_score(text, model, mask):
    # Separate literal-window oracle, no accelerated/factor scoring imports.
    p,q=float(model.alpha).as_integer_ratio()
    answer=1
    for i in range(len(text)-model.order+1):
        if all(k not in mask for k in range(i,i+model.order)):
            answer*=model.counts.get(text[i:i+model.order],0)*q+p
    return answer


def independent_family(ciphertext,cipher,model,mask=()):
    values=[]
    for key in range(26):
        plain=''.join(ALPHABET[((key-ALPHABET.index(c)) if cipher=='beaufort'
                    else (ALPHABET.index(c)+key) if cipher=='variant'
                    else (ALPHABET.index(c)-key))%26] for c in ciphertext)
        values.append((plain,product_score(plain,model,mask)))
    assert len(set(p for p,s in values))==26
    return sorted(values,key=lambda row:(-row[1],row[0]))


def replay(text,recipe):
    # Independent ordinary/scheduled expanded replay. These controls use S only.
    # Ordinary recipes share an alphabet; expanded recipes declare it per stage.
    alphabet=recipe.get('alphabet')
    for stage in recipe['stages']:
        assert stage['operation']=='repeat_substitution'
        key=stage.get('key_pattern',stage.get('key'))
        cipher=stage.get('cipher','vigenere')
        letters=stage.get('alphabet',alphabet)
        assert isinstance(letters,str) and len(letters)==26 and set(letters)==set(ALPHABET)
        text=''.join(letters[((letters.index(key[i%len(key)])-letters.index(c)) if cipher=='beaufort'
                         else (letters.index(c)-letters.index(key[i%len(key)])) if cipher=='variant'
                         else (letters.index(c)+letters.index(key[i%len(key)])))%26]
                     for i,c in enumerate(text))
    return text


def candidate_signature(candidates):
    return [(c['plaintext'],int(c['score_exact'],16)) for c in candidates]


def run_campaign(output,label,body,model,*,production_worker=False):
    manager=RunManager(output/label/'runs')
    campaigns=CampaignManager(manager)
    calls=[]
    original_launch=manager._launch
    def launch(key,job):
        result=original_launch(key,job) if production_worker else execute(job)
        calls.append({'run_id':key,'offset':job['offset'],'next_offset':int(result['next_offset_decimal']),
                      'evaluated':result['evaluated'],'request':copy.deepcopy(job['request']),
                      'plaintexts':[c['plaintext'] for c in result['candidates']]})
        assert len(result['candidates'])==result['evaluated']  # Every authored page is <=13.
        return result
    try:
        with patch.object(manager,'_launch',side_effect=launch):
            if production_worker:
                campaigns.start(body)
                campaigns.thread.join(timeout=35)
            else:
                with patch.object(campaigns,'_task',side_effect=lambda key,job:execute(job)):
                    campaigns.start(body)
                    campaigns.thread.join(timeout=35)
            assert not campaigns.thread.is_alive(), 'Bounded campaign did not finish'
        record=campaigns.view()
        assert record['state']=='completed', record.get('error')
        whole=manager.list_runs()
        snapshots=[]
        replays=0
        for job in record['jobs']:
            snap=job.get('scan_snapshot')
            candidates=job.get('candidates',manager.view(job['run_id'])['candidates'])
            request=job['config']['request']
            for candidate in candidates:
                assert replay(candidate['plaintext'],candidate['encryption_recipe'])==request['ciphertext']
                assert int(candidate['score_exact'],16)==product_score(candidate['plaintext'],model,request.get('score_mask',[]))
                replays+=1
            if snap:
                if snap['whole_family_complete']:
                    cipher=request['stages'][0].get('cipher','vigenere')
                    assert candidate_signature(candidates)==independent_family(request['ciphertext'],cipher,model,request.get('score_mask',[]))[:20]
                else:
                    assert snap['top_k_exact'] is False
                snapshots.append({k:copy.deepcopy(v) for k,v in snap.items() if k!='candidates'})
        source_run=manager.view(record['jobs'][0]['run_id'])
        source_oracle=independent_family('BCDEFG','vigenere',model,body['base']['request'].get('score_mask',[]))
        if source_run['state']=='completed':
            assert candidate_signature(source_run['candidates'])==source_oracle[:20]
            for candidate in source_run['candidates']:
                assert replay(candidate['plaintext'],candidate['encryption_recipe'])=='BCDEFG'
                replays+=1
        unique=len(set(text for call in calls for text in call['plaintexts']))
        return {'production_worker':production_worker,'calls':calls,'run_count':len(whole),
            'job_states':[j['state'] for j in record['jobs']], 'snapshots':snapshots,
            'committed_candidate_evaluations':sum(c['evaluated'] for c in calls),
            'unique_evaluated_plaintexts':unique,'independent_literal_replays':replays,
            'sharing_validation':[j.get('sharing_validation',{}) for j in record['jobs']],
            'all_owner_requests_unchanged':all(call['request']==calls[0]['request'] for call in calls)
        }
    finally:
        campaigns.close()
        manager.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--inputs',action='store_true')
    args=parser.parse_args()
    if args.inputs:
        print(json.dumps(input_paths()))
        return
    if args.output is None:
        parser.error('--output is required unless using --inputs')
    output=args.output.resolve()
    if not output.is_relative_to(ROOT):
        parser.error('output must be a fresh directory inside the workspace')
    output.mkdir(parents=True,exist_ok=False)
    started=time.monotonic()
    before=hashes()
    model=CharacterNgramModel.from_json((ROOT/MODEL).read_text(encoding='utf-8'))
    records={}
    try:
        records['shared_two']=run_campaign(output,'shared-two',plan(),model)
        records['default_off_two']=run_campaign(output,'default-off-two',plan(enabled=False),model)
        records['supplemental_three']=run_campaign(output,'supplemental-three',three_job_plan(),model)
        records['beaufort_negative']=run_campaign(output,'beaufort-negative',plan(size=10,ciphers=('vigenere','variant','beaufort')),model)
        masked=plan()
        masked['base']['request']['score_mask']=[0,2]
        records['masked']=run_campaign(output,'masked',masked,model)
        records['production_worker_two']=run_campaign(output,'production-worker-two',plan(),model,production_worker=True)
        assert [c['offset'] for c in records['shared_two']['calls']]==[0,13]
        assert [c['offset'] for c in records['supplemental_three']['calls']]==[0,10,20]
        assert [c['offset'] for c in records['beaufort_negative']['calls']]==[0,10,0]
        assert records['shared_two']['job_states']==['incomplete','completed']
        assert records['shared_two']['snapshots'][0]['completed_offset_decimal']=='13'
        assert records['shared_two']['snapshots'][0]['whole_family_complete'] is False
        assert records['shared_two']['run_count']==1
        assert records['production_worker_two']['run_count']==1
        assert records['default_off_two']['run_count']==2
        a=independent_family('BCDEFG','vigenere',model)
        b=independent_family('BCDEFG','variant',model)
        assert a==b
        comparison={'independently_completed_recipe_evaluations':len(a)+len(b),
            'independently_completed_unique_plaintexts':len(set(t for t,s in a+b)),
            'shared_candidate_evaluations':records['shared_two']['committed_candidate_evaluations'],
            'shared_unique_plaintexts':records['shared_two']['unique_evaluated_plaintexts'],
            'duplicate_complete_candidate_evaluations_avoided':len(a)+len(b)-records['shared_two']['committed_candidate_evaluations'],
            'comparison_scope':'Two independently completed equivalent recipe rankings versus one completed owner ranking and a separately replayed equivalent recipe; the earlier job snapshot itself stays incomplete.'}
        after=hashes()
        assert before==after, 'Source closure changed; run is invalid'
        result={'schema':'kryptos.campaign-P-audit.v1','status':'passed',
            'assertion_tested':'Within the declared authored CPU cases, compatible jobs extend one original committed coordinate sequence, aliases replay and exact rankings match independent literal enumeration/scoring.',
            'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-started,
            'software':{'python':platform.python_version(),'platform':platform.platform()},
            'inputs_before':before,'inputs_after':after,'comparison':comparison,'records':records,
            'non_claims':['No universal performance improvement','No whole-family proof from a partial ranking','No K4/K5 search or authentication']}
        (output/'results.json').write_text(json.dumps(result,indent=2,allow_nan=False),encoding='utf-8')
        print(json.dumps({'status':'passed','cases':len(records),'comparison':comparison}))
    except Exception as error:
        (output/'failure.json').write_text(json.dumps({'status':'failed','error':str(error),
            'inputs_before':before,'inputs_after':hashes(),'partial_records':records},indent=2),encoding='utf-8')
        raise


if __name__=='__main__':
    main()
