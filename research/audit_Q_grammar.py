"""Fixed Q62/64/65 work comparisons; interpretation is deliberately bounded."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kryptos.recipe_grammar import generate, synthesize


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    choices = [{'operation': 'substitution', 'period': 1, 'cipher': c}
               for c in ('vigenere', 'variant')]
    grammar = generate({'length': 4, 'slots': [choices] * 6})
    assert grammar['complete'] and grammar['represented_complete_recipes'] == 64
    assert grammar['work']['symbolic_transitions'] == 12
    recipes = [[{'operation': 'substitution', 'period': p, 'cipher': c}]
               for p, c in ((1, 'vigenere'), (1, 'beaufort'), (2, 'vigenere'))]
    recipes.append([{'operation': 'gather', 'permutation': [2, 1, 0]}])
    pairs = [{'plaintext': p, 'ciphertext': ''.join(chr(65 + (ord(c) - 64) % 26) for c in p),
              'source': 'frozen authored period-one control'} for p in ('AAA', 'ABC', 'XYZ')]
    reports = [synthesize({'recipes': recipes, 'examples': pairs, 'initial_examples': count})
               for count in (1, 3)]
    for report in reports:
        assert report['complete']
        assert sorted(r['input_index'] for r in report['accepted']) == [0, 2]
    priority_recipes = [[{'operation': 'substitution', 'period': 2, 'cipher': 'beaufort'}],
                        [{'operation': 'gather', 'permutation': [2, 1, 0]},
                         {'operation': 'substitution', 'period': 2}], recipes[0]]
    priority = [synthesize({'recipes': priority_recipes, 'examples': pairs,
                           'priority': enabled, 'stop_after_first': True})
                for enabled in (False, True)]
    for report in priority:
        assert not report['complete'] and report['criterion_first_witness_satisfied']
        assert report['accepted'][0]['input_index'] == 2
    assert [r['work']['recipe_candidates'] for r in priority] == [3, 1]
    result = {
        'schema': 'kryptos.Q-grammar-work.v1', 'all_checks_passed': True,
        'prefixes': {'literal_tree_edges': 126, 'symbolic': grammar},
        'cegis': {'lazy_examples': reports[0], 'all_examples_initially': reports[1]},
        'priority': {'input_order': priority[0], 'shorter_first': priority[1]},
        'limits': ['Fixed authored controls; no universal advantage',
                   'CEGIS may need more solver passes than adding all examples',
                   'First-witness stopping does not exclude the rest of the bank',
                   'Signature calls and input coefficients are counted, not all RREF or serialization operations',
                   'No authenticated K4/K5 plaintext or method']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': True, 'prefix_transitions': 12,
                      'cegis_work': [r['work'] for r in reports],
                      'priority_work': [r['work'] for r in priority]}))


if __name__ == '__main__':
    main()
