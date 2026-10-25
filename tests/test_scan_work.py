"""Independent integer-product oracles for phase O scoring and filtering."""
import itertools
import math
import os
import random
import unittest
from unittest.mock import patch

from kryptos.accelerated import _cpu_rank, _cuda_certified_filter, _measured_backend
from kryptos.certified_scores import overlapping_indices


def literal_rank(affine, offset, count, keep, scoring, order):
    starts, codes, p, q = scoring
    rows = []
    points = itertools.product(*(range(d) for d in affine['domains']))
    for index, point in enumerate(points):
        if index < offset:
            continue
        if index >= offset + count:
            break
        letters = [(base + sum(col[i] * v for col, v in zip(affine['columns'], point))) % 26
                   for i, base in enumerate(affine['base'])]
        factors = []
        for start in starts:
            code = sum(letters[start+j] * 26**(order-1-j) for j in range(order))
            factors.append(codes.get(code, 0)*q+p)
        rows.append((math.prod(factors), ''.join(affine['alphabet'][v] for v in letters), index))
    return [(score, index) for score, word, index in sorted(rows, key=lambda r: (-r[0], r[1], r[2]))[:keep]]


class IncrementalWindowTests(unittest.TestCase):
    def test_masked_carry_pages_zero_factors_and_duplicate_plaintexts(self):
        rng = random.Random(97025)
        for length, order, p in itertools.product((7, 13), (1, 2, 3), (0, 1, 3)):
            affine = {'base': [rng.randrange(26) for _ in range(length)], 'domains': [2, 3, 5],
                      'columns': [[rng.choice((0, 0, 0, 1, 13)) for _ in range(length)] for _ in range(3)],
                      'alphabet': 'BACDEFGHIJKLMNOPQRSTUVWXYZ'}
            starts = [i for i in range(length-order+1) if 3 not in range(i, i+order)]
            codes = {rng.randrange(26**order): rng.randrange(1, 9) for _ in range(30)}
            scoring = (starts, codes, p, 4)
            for offset, count in ((0, 30), (4, 7), (13, 17), (29, 1)):
                work = {}
                got, _ = _cpu_rank(affine, offset, count, min(5, count), scoring, order, work=work)
                full, _ = _cpu_rank(affine, offset, count, min(5, count), scoring, order, incremental=False)
                expected = literal_rank(affine, offset, count, min(5, count), scoring, order)
                self.assertEqual(got, expected)
                self.assertEqual(got, full)
                self.assertLessEqual(work['window_factor_evaluations'], count*len(starts))
                self.assertEqual(work['candidate_evaluations'], count)

    def test_sparse_factor_work_reduction_and_dense_fallback(self):
        affine = {'base': [0]*40, 'domains': [2, 13],
                  'columns': [[13]+[0]*39, [2]+[0]*39], 'alphabet': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'}
        scoring = (list(range(38)), {0: 9, 2*26**2: 7}, 1, 2)
        work, baseline = {}, {}
        got, _ = _cpu_rank(affine, 0, 26, 8, scoring, 3, work=work)
        full, _ = _cpu_rank(affine, 0, 26, 8, scoring, 3, incremental=False, work=baseline)
        self.assertEqual(got, full)
        self.assertEqual(work['window_factor_evaluations'], 38+25)
        self.assertEqual(baseline['window_factor_evaluations'], 38*26)
        dense = dict(affine, columns=[[13]*40, [2]*40])
        work = {}
        got, _ = _cpu_rank(dense, 0, 26, 8, scoring, 3, work=work)
        self.assertEqual(got, literal_rank(dense, 0, 26, 8, scoring, 3))
        self.assertEqual(work['full_rescores'], 26)

    def test_no_scoring_windows_keeps_exact_lexical_ties(self):
        affine = {'base': [0, 1], 'domains': [2, 13],
                  'columns': [[13, 0], [2, 0]], 'alphabet': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'}
        work = {}
        got, _ = _cpu_rank(affine, 0, 26, 10, ([], {}, 1, 1), 3, work=work)
        self.assertEqual(got, literal_rank(affine, 0, 26, 10, ([], {}, 1, 1), 3))
        self.assertEqual(work['window_factor_evaluations'], 0)


class MeasuredBackendTests(unittest.TestCase):
    def test_bounded_comparison_cache_and_mismatch_fallback(self):
        class Model:
            order = 1
        job = {'model': Model()}
        affine = {'base': [0], 'domains': [2, 13], 'columns': [[13], [2]], 'alphabet': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'}
        scoring = ([0], {0: 3}, 1, 1)
        expected, _ = _cpu_rank(affine, 0, 26, 3, scoring, 1)
        with patch('kryptos.accelerated.probe_backend', return_value={'cuda': {'ready': True}}), \
                patch('kryptos.accelerated._cuda_rank', return_value=(expected, 26, {})) as gpu:
            chosen, report = _measured_backend(affine, job, 0, 26, 3, scoring, 'certified')
            self.assertIn(chosen, {'cpu', 'cuda'})
            self.assertEqual(report['sample_count'], 26)
            self.assertEqual(report['calibration_candidate_evaluations_this_call'], 52)
            self.assertTrue(report['exact_sample_agreement'])
            again, cached = _measured_backend(affine, job, 1, 25, 3, scoring, 'certified')
            self.assertEqual(again, chosen)
            self.assertTrue(cached['cache_hit'])
            self.assertEqual(cached['calibration_candidate_evaluations_this_call'], 0)
            self.assertEqual(gpu.call_count, 1)
        with patch('kryptos.accelerated.probe_backend', return_value={'cuda': {'ready': True}}), \
                patch('kryptos.accelerated._cuda_rank', return_value=([(999, 0)], 26, {})):
            chosen, report = _measured_backend(affine, {'model': Model()}, 0, 26, 3, scoring, 'certified')
            self.assertEqual(chosen, 'cpu')
            self.assertIn('disagree', report['fallback_reason'])
            self.assertIsNone(report['calibration_candidate_evaluations_this_call'])
            self.assertEqual(report['calibration_cpu_candidate_evaluations'],26)
            self.assertEqual(report['calibration_candidate_evaluations_upper_bound'],52)

    def test_unavailable_cuda_does_not_calibrate(self):
        with patch('kryptos.accelerated.probe_backend', return_value={'cuda': {'ready': False, 'error': 'absent'}}):
            chosen, report = _measured_backend({}, {}, 0, 50, 3, (), 'certified')
            self.assertEqual(chosen, 'cpu')
            self.assertEqual(report['calibration_candidate_evaluations_this_call'], 0)


@unittest.skipUnless(os.environ.get('KRYPTOS_TEST_CUDA') == '1', 'explicit CUDA test opt-in')
class DeviceCompactionTests(unittest.TestCase):
    def test_uint64_cutoff_and_every_tie_match_integer_oracle(self):
        from kryptos.cuda_environment import load_cupy
        cp = load_cupy()
        rng = random.Random(1025)
        cases = [([0]*64, [0]*64), ([2**64-10]*33, [2**64-1]*33)]
        for size in (1, 17, 256):
            lower = [rng.randrange(2**63, 2**63+1024) for _ in range(size)]
            cases.append((lower, [n+rng.randrange(8) for n in lower]))
        for lower, upper in cases:
            for keep in sorted({1, min(5, len(lower)), len(lower)}):
                expected, threshold = overlapping_indices(lower, upper, keep)
                indices, cutoff, width = _cuda_certified_filter(cp.asarray(lower, dtype=cp.uint64), cp.asarray(upper, dtype=cp.uint64), keep)
                self.assertEqual(indices.get().tolist(), expected)
                self.assertEqual(cutoff, threshold)
                self.assertEqual(width, max(b-a for a, b in zip(lower, upper)))


if __name__ == '__main__':
    unittest.main()
