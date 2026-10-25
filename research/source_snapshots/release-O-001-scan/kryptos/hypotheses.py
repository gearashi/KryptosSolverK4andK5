"""Finite, reproducible recipe grammar; no inferred sculpture mechanism."""
import copy
from itertools import product
import json


def _options(value,name,maximum):
    if not isinstance(value,list) or not 1<=len(value)<=maximum:
        raise ValueError(f"{name} requires 1..{maximum} explicit choices")
    return value


def simplify_routes(stages,length):
    """Compose only adjacent literal gathers; never merge unknown key families."""
    result=[]
    identity=list(range(length))
    for raw in stages:
        stage=copy.deepcopy(raw)
        if stage['operation']=='gather':
            if result and result[-1]['operation']=='gather':
                previous=result.pop()['permutation']
                stage['permutation']=[previous[i] for i in stage['permutation']]
            if stage['permutation']==identity:
                continue
        result.append(stage)
    return result


def generate_configs(base,settings):
    from .__main__ import _target
    from .grid import coordinate_routes
    allowed={'patterns','periods','alphabets','ciphers','routes','width','max_expansions','path_parameters'}
    if not isinstance(settings,dict) or set(settings)-allowed:
        raise ValueError('Unknown hypothesis generator field')
    if base.get('command')!='optimize-plus':
        raise ValueError('Generated families use optimize-plus')
    request=base['request']
    if request.get('layer_model','general')!='general':
        raise ValueError('Grammar requires a general-layer base; scheduled families stay explicit')
    target,text,_,_=_target(request)
    n=len(text)
    patterns=_options(settings.get('patterns',['S','ST','TS','STS']), 'patterns',8)
    if any(not isinstance(p,str) or not 1<=len(p)<=6 or set(p)-{'S','T'} or not 1<=p.count('S')<=3 or p.count('T')>2 for p in patterns):
        raise ValueError('Patterns use S substitutions and T routes, with 1..3 S and at most2 T')
    periods=_options(settings.get('periods',[1,2]),'periods',8)
    if any(type(p) is not int or not 1<=p<=128 for p in periods):
        raise ValueError('Periods must be integers1..128')
    alphabets=_options(settings.get('alphabets',[request.get('alphabet','kryptos')]),'alphabets',4)
    for alphabet in alphabets:
        if not isinstance(alphabet,str) or (alphabet not in ('standard','kryptos') and (len(alphabet)!=26 or set(alphabet)!=set('ABCDEFGHIJKLMNOPQRSTUVWXYZ'))):
            raise ValueError('Invalid generator alphabet')
    ciphers=_options(settings.get('ciphers',['vigenere']),'ciphers',3)
    if any(c not in ('vigenere','beaufort','variant') for c in ciphers):
        raise ValueError('Unsupported substitution equation')
    routes=[]
    path_generations=[]
    route_options=_options(settings.get('routes',['identity','reverse']),'routes',32)
    if route_options.count('paths')>1 or ('path_parameters' in settings and 'paths' not in route_options):
        raise ValueError('Use one paths route token with its path_parameters')
    for raw in route_options:
        if raw=='identity':
            routes.append({'id':'identity','permutation':list(range(n))})
        elif raw=='reverse':
            routes.append({'id':'reverse','permutation':list(reversed(range(n)))})
        elif raw in ('sculpture','paths'):
            if target=='k4':
                from .sculpture import section_cells
                cells=[(c.row,c.column) for c in section_cells('K4')]
                origin='packaged-ordinal-K4'
            else:
                width=settings.get('width')
                if type(width) is not int or not 1<=width<=n:
                    raise ValueError('Custom coordinate routes require an explicit width')
                cells=[divmod(i,width) for i in range(n)]
                origin=f'explicit-ragged-width-{width}'
            if raw=='sculpture':
                routes.extend({'id':origin+'/'+r['aliases'][0],'aliases':r['aliases'],'permutation':r['permutation']} for r in coordinate_routes(cells))
            else:
                from .grid_paths import generate_path_routes
                generated=generate_path_routes(cells,settings.get('path_parameters',{}))
                generated['coordinate_origin']=origin
                if target=='k4':
                    from .sculpture import PACKAGED_LAYOUT_SHA256
                    generated['normalized_dataset_sha256']=PACKAGED_LAYOUT_SHA256
                path_generations.append(generated)
                routes.extend({**r,'id':origin+'/'+r['id']} for r in generated['routes'])
        elif isinstance(raw,dict) and set(raw)=={'id','permutation'} and isinstance(raw['id'],str) and 1<=len(raw['id'])<=100:
            permutation=raw['permutation']
            if not isinstance(permutation,list) or len(permutation)!=n or any(type(i) is not int for i in permutation) or set(permutation)!=set(range(n)):
                raise ValueError('Explicit route must be a full zero-based bijection')
            routes.append(copy.deepcopy(raw))
        else:
            raise ValueError('Route must be identity, reverse, sculpture, paths, or an explicit named permutation')
    if not routes and any('T' in p for p in patterns):
        raise ValueError('No declared grid walk was bijective; no route can enter a cipher search')
    cap=settings.get('max_expansions',4096)
    if type(cap) is not int or not 1<=cap<=4096:
        raise ValueError('max_expansions must be1..4096')
    count=sum(len(alphabets)*(len(periods)*len(ciphers))**p.count('S')*len(routes)**p.count('T') for p in patterns)
    raw_routes=sum(len(r.get('parameter_aliases',[None])) for r in routes)
    before_route_dedup=sum(len(alphabets)*(len(periods)*len(ciphers))**p.count('S')*raw_routes**p.count('T') for p in patterns)
    if before_route_dedup>cap:
        raise ValueError(f'Grammar expands {before_route_dedup} parameter recipes, exceeding declared cap {cap}; narrow choices')
    substitutions=[({'operation':'substitution','period':p,'cipher':c},None) for p,c in product(periods,ciphers)]
    gathered=[({'operation':'gather','permutation':r['permutation']},r) for r in routes]
    configs=[]
    seen={}
    for pattern,alphabet in product(patterns,alphabets):
        pools=[substitutions if symbol=='S' else gathered for symbol in pattern]
        for choices in product(*pools):
            raw=copy.deepcopy([stage for stage,route in choices])
            normalized=simplify_routes(raw,n)
            config=copy.deepcopy(base)
            config['request'].update(stages=normalized,alphabet=alphabet,layer_model='general')
            alias={'pattern':pattern,'alphabet':alphabet,'original_stages':raw}
            if path_generations:
                alias['route_choices']=[{k:copy.deepcopy(v) for k,v in route.items() if k not in ('permutation','mapping')}
                                        for stage,route in choices if route is not None]
                multiplicity=1
                for stage,route in choices:
                    if route is not None:multiplicity*=len(route.get('parameter_aliases',[None]))
                alias['parameter_multiplicity']=multiplicity
            identity=json.dumps(config,sort_keys=True,separators=(',',':'),allow_nan=False)
            if identity in seen:
                configs[seen[identity]]['generation_aliases'].append(alias)
            else:
                seen[identity]=len(configs)
                configs.append({'config':config,'generation_aliases':[alias]})
                if len(configs)>128:
                    raise ValueError('Generated campaign exceeds128 distinct recipes; narrow the grammar')
    return configs,{'schema':'kryptos.hypothesis-grammar.v1','expanded_recipes':count,'distinct_recipes':len(configs),
        'expanded_recipes_before_path_dedup':before_route_dedup,'path_duplicate_recipe_expansions_avoided':before_route_dedup-count,
        'path_generation':path_generations,
        'literal_duplicates_removed':count-len(configs),'routes':routes,'settings':copy.deepcopy(settings),
        'interpretation':'Explicit finite grammar; S has independent unknown keys, T is a literal gather. Only adjacent gathers/identity routes simplify. Coordinates are ordinal hypotheses, not measured geometry. No language-score or crib-based tuning in generation.'}
