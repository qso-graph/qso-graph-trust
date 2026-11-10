#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic regression tests for private artifacts and content-free classification."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('differential', Path(__file__).with_name('cabrillo-differential.py'))
DIFF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIFF)


class DifferentialTests(unittest.TestCase):
    def test_time_normalization(self):
        with tempfile.TemporaryDirectory() as folder:
            left, right = Path(folder) / 'left', Path(folder) / 'right'
            for compact, display in [('0000', '00:00:00Z'), ('1830', '18:30:00Z'),
                                     ('2359', '23:59:00Z'), ('183055', '18:30:55Z')]:
                left.write_text(f'Z0TEST\t20m\tCW\t2026-11-03\t{compact}\t14.042000\n')
                right.write_text(f'Z0TEST\t20m\tCW\t2026-11-03\t{display}\t14.042\n')
                self.assertEqual(DIFF.normalized(left), DIFF.normalized(right))
            # Normalization preserves seconds and order/multiplicity.
            left.write_text('Z0TEST\t20m\tCW\t2026-11-03\t183000\t14.042\n')
            self.assertNotEqual(DIFF.normalized(left), DIFF.normalized(right))

    def test_refusals_classified_by_fixed_kind(self):
        accepted = ([('synthetic',)], [('signature',)])
        for reason in DIFF.SPEC_REFUSALS:
            for reference in [None, (None, []), accepted]:
                self.assertEqual(DIFF.classify((None, []), reference, reason),
                                 ('QGT right by ADIF or Cabrillo', reason))
        # Unrecognized failures cannot be adjudicated away as a specification refusal.
        for reason in ['invalid CONTEST', 'PRIVATE-SENTINEL', 'unexpected_reader_error']:
            self.assertEqual(DIFF.classify((None, []), accepted, reason),
                             ('QGT wrong', 'unexpected_reader_error'))
        self.assertEqual(DIFF.classify((None, []), accepted, 'qso_conversion'),
                         ('QGT refused by LoTW validation', 'qso_conversion'))
        self.assertIsNone(DIFF.classify(accepted, accepted, None))
        self.assertEqual(DIFF.classify(accepted, ([('different',)], []), None),
                         ('QGT wrong', 'reader_disagreement'))
        self.assertEqual(DIFF.classify(accepted, (accepted[0], []), None),
                         ('QGT wrong', 'signing_disagreement'))
        self.assertEqual(DIFF.classify(accepted, (None, []), None),
                         ('QGT right by ADIF or Cabrillo', 'reference_refusal'))

    def test_artifact_reason_never_becomes_public_content(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'artifact'
            for reason in DIFF.SPEC_REFUSALS:
                path.write_text(f'REFUSED\t{reason}\n')
                self.assertEqual(DIFF.refusal_kind(path), reason)
                self.assertIsNone(DIFF.normalized(path))
            path.write_text('REFUSED\tqso_conversion\n')
            self.assertEqual(DIFF.refusal_kind(path), 'qso_conversion')
            path.write_text('REFUSED\tPRIVATE-SENTINEL\n')
            kind = DIFF.refusal_kind(path)
            self.assertEqual(kind, 'unexpected_reader_error')
            self.assertNotIn('PRIVATE', str(DIFF.classify((None, []), None, kind)))
            path.write_text('REFUSED\n')
            self.assertEqual(DIFF.refusal_kind(path), 'reference_refusal')
            self.assertIsNone(DIFF.normalized(path))


class LabArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(['cargo', 'build', '-q', '-p', 'qso-graph-trust-custody',
                                 '--bin', 'qgt-cabrillo-lab', '--locked'], cwd=DIFF.ROOT, capture_output=True)
        if result.returncode:
            raise RuntimeError('Synthetic lab driver build failed')

    def test_no_qso_is_silently_dropped(self):
        with tempfile.TemporaryDirectory() as folder:
            prefix = Path(folder) / 'output'
            fixtures = DIFF.ROOT / 'tests/corpus/cabrillo/refused'
            for path in sorted(fixtures.glob('*.log')):
                with self.subTest(fixture=path.name):
                    result = subprocess.run([str(DIFF.ROOT / 'target/debug/qgt-cabrillo-lab'),
                                             str(path), str(prefix), str(DIFF.ROOT / 'tests/corpus')],
                                            capture_output=True)
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout + result.stderr, b'')
                    structural = path.stem == 'misplaced-end'
                    reason, line = ('start', 1) if structural else ('qso_conversion', 6)
                    self.assertEqual(prefix.with_suffix('.records').read_text(), f'REFUSED\t{reason}\n')
                    self.assertEqual(prefix.with_suffix('.tq7').read_bytes(), b'')
                    refusal = prefix.with_suffix('.refusal').read_text()
                    self.assertTrue(refusal.startswith(f'line {line}: '))
                    self.assertNotIn('Q0TEST', refusal)
                    self.assertNotIn('Z0TEST', refusal)

    def test_sponsor_layouts_both_sides(self):
        paths = sorted((DIFF.ROOT / 'tests/corpus/cabrillo').glob('sponsor-*.log'))
        self.assertEqual(len(paths), 18)
        with tempfile.TemporaryDirectory() as folder:
            prefix = Path(folder) / 'output'
            for path in paths:
                with self.subTest(fixture=path.name):
                    result = subprocess.run([str(DIFF.ROOT / 'target/debug/qgt-cabrillo-lab'),
                                             str(path), str(prefix), str(DIFF.ROOT / 'tests/corpus')],
                                            capture_output=True)
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout + result.stderr, b'')
                    values = DIFF.normalized(prefix.with_suffix('.records'))
                    self.assertIsNotNone(values)
                    self.assertEqual(len(values), 1)
                    expected = ('Z0TEST' if path.stem.startswith('sponsor-arrl-160-') else
                                'Z0X' if path.stem.endswith('-a') else 'ZZ01')
                    self.assertEqual(values[0][0], expected)
                    self.assertEqual(len(DIFF.contacts(prefix.with_suffix('.tq7'))), 1)

    def test_lab_emits_fixed_refusal_kind_without_content(self):
        with tempfile.TemporaryDirectory() as folder:
            path, prefix = Path(folder) / 'input', Path(folder) / 'output'
            cases = [
                (b'START-OF-LOG: PRIVATE-SENTINEL\n', 'start'),
                (b'START-OF-LOG: 3.0\nCONTEST: PRIVATE SENTINEL\n', 'contest'),
                (b'START-OF-LOG: 3.0\nCONTEST: UNKNOWN\nSOAPBOX: \xff\n', 'encoding'),
                (b'START-OF-LOG: 3.0\nCONTEST: CQ-WW-CW\nQSO: 14000 LS 2026-11-03 1830 QG0TEST 599 4 Z0TEST\nEND-OF-LOG:\n', 'mode'),
                (b'START-OF-LOG: 3.0\nCONTEST: UNKNOWN\nQSO: 14000 CW 2026-11-03 1830 QG0TEST 599 4 599\nEND-OF-LOG:\n', 'no_received_call'),
            ]
            for data, reason in cases:
                path.write_bytes(data)
                result = subprocess.run([str(DIFF.ROOT / 'target/debug/qgt-cabrillo-lab'),
                                         str(path), str(prefix), str(DIFF.ROOT / 'tests/corpus')],
                                        capture_output=True)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout + result.stderr, b'')
                self.assertEqual(prefix.with_suffix('.records').read_text(), f'REFUSED\t{reason}\n')
                self.assertEqual(prefix.with_suffix('.tq7').read_bytes(), b'')
                self.assertEqual(DIFF.classify((None, []), None, DIFF.refusal_kind(prefix.with_suffix('.records'))),
                                 ('QGT right by ADIF or Cabrillo', reason))


if __name__ == '__main__':
    unittest.main()
