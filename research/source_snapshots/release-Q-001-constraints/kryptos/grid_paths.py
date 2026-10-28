"""Bounded parameterized walks over occupied ordinal inscription cells.

These are hypotheses, not a recovered physical mechanism. At every step try
straight, then successive quarter turns in the chosen sense. Holes and visited
cells block a move. Toroidal wrap uses the occupied set's bounding rectangle;
it never supplies a missing cell. Only full bijective walks become routes.
"""
from itertools import product

from .grid import _cells

DIRECTIONS={"north":(-1,0),"east":(0,1),"south":(1,0),"west":(0,-1)}
HEADINGS=tuple(DIRECTIONS)


def _parameters(cells,parameters):
    cells=_cells(cells)
    if not isinstance(parameters,dict) or set(parameters)!={"start_index","direction","turn","wrap"}:
        raise ValueError("A path requires start_index, direction, turn and wrap")
    if type(parameters["start_index"]) is not int or not 0<=parameters["start_index"]<len(cells):
        raise ValueError("start_index must identify an occupied cell")
    if parameters["direction"] not in HEADINGS or parameters["turn"] not in ("right","left") or parameters["wrap"] not in ("none","toroidal"):
        raise ValueError("Use a cardinal direction, left/right turns and none/toroidal wrap")
    return cells


def path_route(cells,parameters):
    """Walk one deterministic parameter tuple, reporting a trapped prefix."""
    cells=_parameters(cells,parameters)
    lookup={cell:i for i,cell in enumerate(cells)}
    r0,c0=min(r for r,c in cells),min(c for r,c in cells)
    height=max(r for r,c in cells)-r0+1
    width=max(c for r,c in cells)-c0+1
    current=parameters["start_index"]
    heading=HEADINGS.index(parameters["direction"])
    turn=1 if parameters["turn"]=="right" else -1
    path=[current]; visited={current}; attempts=0
    while len(path)<len(cells):
        for quarter in range(4):
            chosen=(heading+turn*quarter)%4
            dr,dc=DIRECTIONS[HEADINGS[chosen]]
            r,c=cells[current]; nxt=(r+dr,c+dc)
            if parameters["wrap"]=="toroidal":
                nxt=(r0+(nxt[0]-r0)%height,c0+(nxt[1]-c0)%width)
            attempts+=1
            target=lookup.get(nxt)
            if target is not None and target not in visited:
                path.append(target);visited.add(target);current=target;heading=chosen
                break
        else:
            break
    complete=len(path)==len(cells)
    if complete and sorted(path)!=list(range(len(cells))):
        raise AssertionError("A completed path must be a full bijection")
    return {"parameters":dict(parameters),"complete":complete,
            "permutation":path if complete else None,"visited_prefix":path,
            "neighbor_attempts":attempts,"stop_reason":"all_occupied_cells" if complete else "trapped_before_coverage",
            "unvisited_indices":[i for i in range(len(cells)) if i not in visited]}


def replay_path(cells,parameters,permutation):
    """Independent literal coordinate replay of a claimed complete walk.

    This does not call path_route or trust its completion flag. It reconstructs
    the available next coordinates in priority order from the supplied path.
    """
    cells=_parameters(cells,parameters)
    if (not isinstance(permutation,(list,tuple)) or any(type(i) is not int for i in permutation)
            or sorted(permutation)!=list(range(len(cells))) or permutation[0]!=parameters["start_index"]):
        raise ValueError("Expected a full gather beginning at the declared start")
    low=[min(cell[a] for cell in cells) for a in (0,1)]
    span=[max(cell[a] for cell in cells)-low[a]+1 for a in (0,1)]
    heading=DIRECTIONS[parameters["direction"]]
    seen={permutation[0]}
    for current,following in zip(permutation,permutation[1:]):
        vector=heading
        selected=None
        for _ in range(4):
            coordinate=tuple(cells[current][a]+vector[a] for a in (0,1))
            if parameters["wrap"]=="toroidal":
                coordinate=tuple(low[a]+(coordinate[a]-low[a])%span[a] for a in (0,1))
            if coordinate in cells:
                index=cells.index(coordinate)
                if index not in seen:
                    selected=index;heading=vector
                    break
            dr,dc=vector
            vector=(dc,-dr) if parameters["turn"]=="right" else (-dc,dr)
        if selected!=following:
            raise ValueError("Gather disagrees with deterministic path priority")
        seen.add(following)
    return {"verified":True,"visited_cells":len(seen),"full_bijection":True,
            "convention":"output[j] = input[permutation[j]]"}


def generate_path_routes(cells,settings):
    """Enumerate the entire declared finite parameter set before deduplication."""
    cells=_cells(cells)
    allowed={"start_indices","directions","turns","wraps","max_hypotheses"}
    if not isinstance(settings,dict) or set(settings)-allowed:
        raise ValueError("Unknown grid path setting")
    choices={"start_indices":settings.get("start_indices",[0]),
             "directions":settings.get("directions",["east","south"]),
             "turns":settings.get("turns",["right"]),"wraps":settings.get("wraps",["none"])}
    for name,values in choices.items():
        maximum=32 if name=="start_indices" else 4 if name=="directions" else 2
        if not isinstance(values,list) or not 1<=len(values)<=maximum:
            raise ValueError(f"{name} requires1..{maximum} explicit choices")
        invalid=(any(type(v) is not int or not 0<=v<len(cells) for v in values) if name=="start_indices"
                 else any(not isinstance(v,str) for v in values))
        if invalid:
            raise ValueError("Invalid path parameter choice")
        if len(set(values))!=len(values):
            raise ValueError("Path parameter choices must be distinct")
    cap=settings.get("max_hypotheses",512)
    if type(cap) is not int or not 1<=cap<=512:
        raise ValueError("max_hypotheses must be1..512")
    count=1
    for values in choices.values():count*=len(values)
    if count>cap or count*len(cells)>200000:
        raise ValueError("Declared grid paths exceed the hypothesis or occupied-cell work cap")
    grouped={};rejected=[];attempts=0;valid=0
    for start,direction,turn,wrap in product(*choices.values()):
        parameters={"start_index":start,"direction":direction,"turn":turn,"wrap":wrap}
        record=path_route(cells,parameters)
        attempts+=record["neighbor_attempts"]
        if not record["complete"]:
            rejected.append(record)
            continue
        valid+=1
        signature=tuple(record["permutation"])
        if signature not in grouped:
            grouped[signature]={"id":f"path-{len(grouped)+1}","permutation":list(signature),"parameter_aliases":[],
                "mapping":[{"output_index":j,"input_index":i,"row":cells[i][0],"column":cells[i][1]} for j,i in enumerate(signature)]}
        grouped[signature]["parameter_aliases"].append(parameters)
    return {"schema":"kryptos.grid-paths.v1","cells":[list(c) for c in cells],"settings":choices,
            "raw_hypotheses":count,"bijective_hypotheses":valid,"nonbijective_hypotheses":len(rejected),
            "distinct_routes":len(grouped),"duplicate_bijective_routes_removed":valid-len(grouped),
            "neighbor_attempts":attempts,"routes":list(grouped.values()),"rejected":rejected,
            "interpretation":"Complete declared parameter product; trapped walks rejected and identical bijections merged before cipher work. Coordinates are transcription ordinals, not measured3D geometry or an authenticated Kryptos mechanism."}
