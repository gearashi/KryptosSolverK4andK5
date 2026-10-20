"""Inspect identifiable plaintexts and quantify flexibility, without key search."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kryptos.data import K4_CIPHERTEXT, K4_CRIBS
from research.layer_constraints import check_layers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run = json.loads((ROOT / "research/runs/layers-001/results.json").read_text())
    known = {crib["start"] - 1 + n: ch for crib in K4_CRIBS for n, ch in enumerate(crib["text"])}
    forest_fits = 0
    nonforest_fits = 0
    determined = []
    for row in run["records"]:
        for model in row["models"]:
            if not model["feasible"]:
                continue
            cycles = 24 - model["period_a"] - model["period_b"] + model["free_components"]
            assert cycles >= 0
            forest_fits += cycles == 0
            nonforest_fits += cycles > 0
            if model["free_components"] == 1 and any(alias.startswith("K3-inspired") for alias in row["aliases"]):
                result = check_layers(K4_CIPHERTEXT, known, run["alphabet"], row["order"],
                                      [i - 1 for i in row["source_positions_one_based"]],
                                      model["period_a"], model["period_b"])
                assert result["feasible"]
                determined.append({"aliases": row["aliases"], "order": row["order"],
                                   "period_a": model["period_a"], "period_b": model["period_b"],
                                   "independent_cycle_constraints": cycles,
                                   "plaintext": result["representative_plaintext"],
                                   "representative_keys": result["keys"]})
    result = {"checkpoint": "K4-20261012-E", "base_checkpoint": "K4-20261012-D",
              "forest_fits": forest_fits, "nonforest_fits": nonforest_fits,
              "interpretation": "A forest has no cycle consistency check: any crib values can be fitted by its keys. One connected component leaves only a key gauge freedom, which cancels from every plaintext character in this model.",
              "determined_k3_adaptation_plaintexts": determined,
              "non_claims": ["Cipher structure remains hypothetical", "No full plaintext is authenticated", "The number of fits is not a probability or ranking"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Forest fits:", forest_fits, "Nonforest fits:", nonforest_fits)
    for item in determined:
        print(item["aliases"][0], item["order"], item["period_a"], item["period_b"],
              "cycles", item["independent_cycle_constraints"], item["plaintext"])


if __name__ == "__main__":
    main()
