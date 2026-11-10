#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline Cabrillo reading/signing differential; public output contains counts only.

uv run --no-project python scripts/cabrillo-differential.py --synthetic --qgt-only
uv run --no-project python scripts/cabrillo-differential.py --archive /path/to/archive --count 5000

Real logs are mounted read-only; private artifacts live in an owner-only temporary directory,
removed after the run. The reference driver is built ONLY inside the network-disabled container.
Fixed refusal kinds classify specification violations automatically. Unknown refusal kinds and
reader/signing disagreements count as QGT wrong and cause a nonzero exit.
"""
import argparse
import collections
import decimal
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
CATEGORIES = ('QGT right by ADIF or Cabrillo', 'QGT refused by LoTW validation', 'QGT wrong')
# Closed vocabulary: neither artifact content nor reviewer prose becomes a public report key.
SPEC_REFUSALS = frozenset({
    'input_limit', 'line_limit', 'encoding', 'after_end', 'separator', 'tag', 'value_limit',
    'start', 'repeated_start', 'end', 'contest_order', 'contest', 'before_contest',
    'record_limit', 'field_limit', 'missing_start', 'missing_contest', 'missing_end',
    'qso_fields', 'incomplete_qso', 'no_received_call', 'ambiguous_received_call',
    'guessed_exchange', 'missing_received_call', 'call_syntax', 'date_time', 'mode',
    'frequency', 'band', 'qso_ascii', 'different_received_call_field',
})


def refusal_kind(path):
    with path.open(encoding='utf-8') as stream:
        first = stream.readline().rstrip('\n')
    if first == 'REFUSED':
        return 'reference_refusal'
    if first.startswith('REFUSED\t'):
        kind = first.partition('\t')[2]
        return kind if kind in SPEC_REFUSALS or kind == 'qso_conversion' else 'unexpected_reader_error'
    return None


def classify(qgt, reference, reason):
    if reason == 'qso_conversion':
        return 'QGT refused by LoTW validation', reason
    if reason is not None:
        if reason in SPEC_REFUSALS:
            return 'QGT right by ADIF or Cabrillo', reason
        return 'QGT wrong', 'unexpected_reader_error'
    if reference is not None and reference[0] is None:
        return 'QGT right by ADIF or Cabrillo', 'reference_refusal'
    if reference is not None and reference != qgt:
        return 'QGT wrong', 'reader_disagreement' if reference[0] != qgt[0] else 'signing_disagreement'
    return None


def run(command, **kw):
    result = subprocess.run(command, capture_output=True, **kw)
    if result.returncode:
        raise SystemExit('Differential tool failed; no log data printed')
    return result


def header(path):
    with path.open('rb') as stream:
        b = stream.read(16384)
    if not re.search(rb'(?i)START-OF-LOG:', b):
        return None
    c = re.search(rb'(?im)^\s*CONTEST:\s*([^\r\n]+)', b)
    v = re.search(rb'(?i)START-OF-LOG:\s*([23]\.\d+)', b)
    return (c[1].strip().upper() if c else b'', v[1] if v else b'')


def sample(archive, count):
    # Stratify across contest AND version. Select without depending on traversal order or calls.
    buckets = collections.defaultdict(list)
    for p in sorted(archive.rglob('*')):
        if not p.is_file() or p.is_symlink() or p.suffix.lower() not in ('.log', '.cbr', '.txt', '.cabrillo'):
            continue
        h = header(p)
        if h:
            buckets[h].append(p)
    result = []
    for i in range(max(map(len, buckets.values()), default=0)):
        for key in sorted(buckets):
            if i < len(buckets[key]):
                result.append(buckets[key][i])
                if len(result) == count:
                    if not any(header(p)[1].startswith(b'2.') for p in result):
                        raise SystemExit('Sample has no legacy v2 logs')
                    return result
    raise SystemExit('Archive has fewer eligible logs than requested')


def normalized(path):
    result = []
    for line in path.read_text(errors='replace').splitlines():
        if line == 'REFUSED' or line.startswith('REFUSED\t'):
            return None
        fields = line.upper().split('\t')
        if len(fields) != 6:
            raise SystemExit('Invalid private reader artifact')
        call, band, mode, date, time, freq = fields
        time = time.removesuffix('Z').replace(':', '').ljust(6, '0')
        try:
            freq = str(decimal.Decimal(freq).normalize()) if freq and freq != 'LIGHT' else ''
        except decimal.InvalidOperation:
            freq = 'INVALID'
        result.append((call, band, mode, date, time, freq))
    return result


def contacts(path):
    data = path.read_bytes() if path.exists() else b''
    at, record, result = 0, {}, []
    while at < len(data):
        start = data.find(b'<', at)
        if start < 0:
            break
        end = data.find(b'>', start)
        if end < 0:
            raise SystemExit('Malformed signed reference artifact')
        tag = data[start+1:end].upper().split(b':')
        at = end + 1
        if tag[0] == b'EOR':
            if record.get(b'REC_TYPE') == b'tCONTACT':
                result.append(tuple(record.get(k, b'') if k == b'SIGN_LOTW_V2.0' else record.get(k, b'').upper() for k in (
                    b'CALL', b'BAND', b'MODE', b'QSO_DATE', b'QSO_TIME', b'FREQ',
                    b'SIGNDATA', b'SIGN_LOTW_V2.0')))
            record = {}
        elif len(tag) >= 2:
            length = int(tag[1])
            record[tag[0]] = data[at:at+length]
            at += length
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path)
    p.add_argument('--synthetic', action='store_true')
    p.add_argument('--qgt-only', action='store_true')
    p.add_argument('--count', type=int, default=5000)
    p.add_argument('--image', choices=['localhost/qgt-tqsllib:2.8.7', 'localhost/qgt-tqsllib-asan:2.8.7'], default='localhost/qgt-tqsllib:2.8.7')
    p.add_argument('--report', type=Path, help='Counts by fixed reason kind, without log content, digests, or paths')
    args = p.parse_args()
    archive = (ROOT / 'tests/corpus/cabrillo' if args.synthetic else args.archive)
    if archive is None or (not args.synthetic and args.count < 5000):
        p.error('use --synthetic or --archive with --count >= 5000')
    archive = archive.resolve()
    paths = sorted(archive.glob('*.log')) if args.synthetic else sample(archive, args.count)
    if args.synthetic and len(paths) != 38:
        raise SystemExit('Expected 38 synthetic fixtures')
    run(['cargo', 'build', '-q', '-p', 'qso-graph-trust-custody', '--bin', 'qgt-cabrillo-lab', '--locked'], cwd=ROOT)
    counts = collections.Counter()
    reasons = {category: collections.Counter() for category in CATEGORIES}

    def tally(finding):
        if finding is not None:
            category, reason = finding
            counts[category] += 1
            reasons[category][reason] += 1
    with tempfile.TemporaryDirectory(prefix='qgt-cabrillo-diff-') as folder:
        work = Path(folder)
        os.chmod(work, 0o700)
        (work / 'qgt').mkdir(); (work / 'reference').mkdir()
        manifest = []
        qgt = []
        for i, path in enumerate(paths):
            relative = str(path.relative_to(archive))
            if '\n' in relative or '\t' in relative:
                raise SystemExit('Unsupported archive path')
            manifest.append(f'{i}\t{relative}\n')
            prefix = work / 'qgt' / str(i)
            run([str(ROOT / 'target/debug/qgt-cabrillo-lab'), str(path), str(prefix), str(ROOT / 'tests/corpus')])
            values = normalized(prefix.with_suffix('.records'))
            signed = contacts(prefix.with_suffix('.tq7'))
            reason = refusal_kind(prefix.with_suffix('.records'))
            qgt.append(((values, signed), reason))
            tally(classify((values, signed), None, reason))
            counts['QGT accepted records'] += len(values or [])
            counts['QGT signed QSOs'] += len(signed)
            counts['QGT refused logs'] += values is None
            if args.synthetic and (not values or len(signed) != len(values)):
                raise SystemExit('Synthetic fixture did not read and sign completely')
        (work / 'manifest').write_text(''.join(manifest))
        if not args.qgt_only:
            # label=disable rather than :z/:Z: a relabel would change the read-only archive's and this
            # checkout's SELinux labels for every other user of them.
            run(['podman', 'run', '--rm', '--network=none', '--security-opt', 'label=disable',
                 '-e', f'QGT_REFERENCE_SANITIZERS={int("asan" in args.image)}',
                 '-v', f'{archive}:/logs:ro', '-v', f'{ROOT / "tests/corpus"}:/corpus:ro',
                 '-v', f'{ROOT / "tests/tqsllib/qgt-tqsllib.cpp"}:/driver.cpp:ro',
                 '-v', f'{ROOT / "tests/tqsllib/cabrillo-differential.sh"}:/run.sh:ro',
                 '-v', f'{work / "manifest"}:/manifest:ro', '-v', f'{work / "reference"}:/out',
                 args.image, 'bash', '/run.sh'])
            for i in range(len(paths)):
                prefix = work / 'reference' / str(i)
                ref = (normalized(prefix.with_suffix('.records')), contacts(prefix.with_suffix('.tq7')))
                actual, reason = qgt[i]
                if reason is None:
                    counts['reader agreements'] += ref[0] == actual[0]
                    counts['signature agreements'] += ref[1] == actual[1]
                    if ref == actual:
                        counts['agreements'] += 1
                    else:
                        tally(classify(actual, ref, reason))
        counts['logs'] = len(paths)
        counts['v2 logs'] = sum(header(x)[1].startswith(b'2.') for x in paths)
        counts['contests'] = len({header(x)[0] for x in paths})
        counts['reference logs compared'] = 0 if args.qgt_only else len(paths)
        for category in CATEGORIES:
            counts[category] += 0
        report = {'counts': dict(sorted(counts.items())),
                  'reasons': {category: dict(sorted(kinds.items())) for category, kinds in reasons.items()}}
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    return int(counts['QGT wrong'] > 0)


if __name__ == '__main__':
    raise SystemExit(main())
