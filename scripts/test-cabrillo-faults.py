#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove Cabrillo checks with temporary faults, restoring source even on failure."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
READER = ROOT / 'crates/qso-graph-trust/src/cabrillo.rs'
DISPATCH = ROOT / 'crates/qso-graph-trust/src/records.rs'
HARNESS = ROOT / 'scripts/cabrillo-differential.py'
LAB = ROOT / 'crates/qso-graph-trust-custody/src/bin/qgt-cabrillo-lab.rs'
EXCHANGES = ROOT / 'data/adif-318/exchanges.tsv'
TABLES = ROOT / 'crates/qso-graph-trust/src/cabrillo_tables.rs'
CASES = [
    # ARRL 160's two cited positions are chosen by a strict majority; requiring a plausible call on
    # every QSO would refuse a log for one 1x1 special-event call.
    (READER, '.find(|&i| alternatives[i] > total / 2 && alternatives[1 - i] < total.div_ceil(2));',
     '.find(|&i| alternatives[i] == total && alternatives[1 - i] < total.div_ceil(2));',
     'arrl_160_majority_reads_a_one_by_one_call_from_the_chosen_position'),
    (READER, 'if candidates.next().is_some() {', 'if false {', 'ambiguous_guess_is_refused_on_every_line'),
    (READER, '(*low..=*high).contains(&hz)', '(*low..*high).contains(&hz)', 'adif_band_edges_are_inclusive_and_exact'),
    (DISPATCH, 'return crate::cabrillo::parse(input);',
     'return crate::cabrillo::parse(input).or_else(|_| parse_adi(input));', 'a_cabrillo_claim_is_never_retried_as_adi'),
    # LS is the synthetic test's offending mode. The bounded type cannot hold arbitrary input;
    # planting the literal value in Display proves that even a static content leak is caught.
    (DISPATCH, 'Self::Mode => f.write_str("QSO mode must be one of CW, PH, FM, RY, DG")',
     'Self::Mode => f.write_str("QSO mode must be one of CW, PH, FM, RY, DG; offending value LS")',
     'refusals_name_physical_lines_and_never_echo_values'),
    (HARNESS, "time = time.removesuffix('Z').replace(':', '').ljust(6, '0')",
     'time = time', 'DifferentialTests.test_time_normalization'),
    # A sampled, syntactically valid unknown identifier must reach inference.
    (READER, 'if value.is_empty()',
     'if value == "2026-UNKNOWN" || value.is_empty()',
     'contest_specification_boundary_and_sampled_values'),
    (DISPATCH, 'if !content.starts_with(b"<") && crate::cabrillo::claims(content) {',
     'if content.get(..13).is_some_and(|p| p.eq_ignore_ascii_case(b"START-OF-LOG:")) {',
     'misplaced_markers_claim_cabrillo_instead_of_empty_adi'),
    (LAB, '                return Ok(());', '                continue;',
     'LabArtifactTests.test_no_qso_is_silently_dropped'),
    (EXCHANGES, 'ARRL-DIGI\t6\thttps://contests.arrl.org/ContestRules/Digital-Rules.pdf',
     'ARRL-DIGI\t6\tguessed', 'LabArtifactTests.test_sponsor_layouts_both_sides'),
]


def test(path, name):
    if path in (HARNESS, LAB, EXCHANGES):
        command = ['uv', 'run', '--no-project', 'python',
                   'scripts/test_cabrillo_differential.py', name]
    else:
        command = ['cargo', 'test', '-p', 'qso-graph-trust', '--lib', '--all-features', '--locked',
                   f'cabrillo::tests::{name}', '--', '--exact']
    return subprocess.run(command, cwd=ROOT, capture_output=True)


def main():
    for path, before, after, name in CASES:
        original = path.read_text()
        original_tables = TABLES.read_bytes()
        assert original.count(before) == 1, name
        try:
            path.write_text(original.replace(before, after))
            if path == EXCHANGES:
                subprocess.run(['uv', 'run', '--no-project', 'python', 'scripts/gen-cabrillo-tables.py'],
                               cwd=ROOT, check=True, capture_output=True)
            result = test(path, name)
            # A compiler/import failure is not evidence that the regression test caught a fault.
            expected = (b'FAILED (failures=' in result.stderr if path in (HARNESS, LAB, EXCHANGES) else
                        b'test result: FAILED. 0 passed; 1 failed;' in result.stdout)
            assert result.returncode and expected, name
        finally:
            path.write_text(original)
            if path == EXCHANGES:
                TABLES.write_bytes(original_tables)
        assert test(path, name).returncode == 0, name
        print(f'{name}: planted fault caught; restored source passes', flush=True)
    print(f'{len(CASES)} planted faults caught; {len(CASES)} restored tests pass')


if __name__ == '__main__':
    main()
