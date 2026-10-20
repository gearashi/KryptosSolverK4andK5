"""Deduplicate existing fully forced strings; rank their non-crib English only."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.scoring import english_score, SCORE_DESCRIPTION


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    names = ["research/runs/prediction-001/results.json", "kryptos/scoring.py",
             "research/inspect_complete_predictions.py"]
    paths = [ROOT / name for name in names]
    if args.output.resolve() in {path.resolve() for path in paths}:
        raise ValueError("output cannot overwrite an input")
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest()
              for name, path in zip(names, paths)}
    source = json.loads(paths[0].read_text(encoding="utf-8"))
    unknown = {i - 1 for i in source["unknown_positions_one_based"]}
    excluded = set(range(97)) - unknown
    assert len(unknown) == 73 and len(excluded) == 24
    groups = {}
    count = 0
    for row in source["records"]:
        if row["full_cribs"]["forced_unknown_count"] != 73:
            continue
        count += 1
        plain = row["full_cribs"]["prediction_mask"]
        assert len(plain) == 97 and "?" not in plain
        for crib in source["cribs"]:
            start = crib["start"] - 1
            assert plain[start:start + len(crib["text"])] == crib["text"]
        groups.setdefault(plain, []).append({k: row[k] for k in
            ("model_id", "source_route_record_index", "route_aliases", "order", "period_a", "period_b")})
    assert count == source["full_crib_summary"]["models_forcing_all_73_unknown_letters"]
    ranked = sorted([{"plaintext": plain, "unknown_only_mask": "".join(
        char if i in unknown else "." for i, char in enumerate(plain)),
        "english_score": english_score(plain, excluded), "model_count": len(models),
        "models": models} for plain, models in groups.items()],
        key=lambda row: (-row["english_score"], row["plaintext"]))
    assert sum(row["model_count"] for row in ranked) == count
    assert hashes == {name: hashlib.sha256(path.read_bytes()).hexdigest()
                      for name, path in zip(names, paths)}
    result = {"input_hashes": hashes, "inputs_unchanged": True,
        "fully_forced_model_count": count, "distinct_plaintexts": len(ranked),
        "scored_characters_per_plaintext": 73,
        "excluded_positions_one_based": [i + 1 for i in sorted(excluded)],
        "score_description": SCORE_DESCRIPTION,
        "scope": "Existing complete strings only. Identical plaintexts grouped; no equivalence claim about their generating cipher systems. No new search.",
        "non_claims": ["English rank is not authentication, a calibrated probability, or a rejection of other languages or an intermediate encoding.",
                       "Partial prediction masks are not deduplicated: identical masks may hide different correlations."],
        "ranked_plaintexts": ranked}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"fully_forced_models": count, "distinct_plaintexts": len(ranked),
                      "top_five": [{k: row[k] for k in ("english_score", "unknown_only_mask", "model_count")}
                                   for row in ranked[:5]]}, indent=2))


if __name__ == "__main__":
    main()
