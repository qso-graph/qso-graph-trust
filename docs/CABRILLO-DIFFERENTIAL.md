<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Cabrillo differential evidence

Decision [0016](decisions/0016-cabrillo.md) reads Cabrillo logs through the same ADIF QSO and signing
path as ADI and ADX. This page records how QG Trust's reader and signer were compared with tqsllib
2.8.7, the answer key, and the result.

## Result

5,000 public contest logs, 39 contests, 1,697 of them Cabrillo v2:

| Outcome | Logs |
|---|---:|
| Read and signed exactly as tqsllib reads and signs them | 3,537 |
| Read or signed differently from tqsllib (`QGT wrong`) | **0** |
| Refused: not in the Cabrillo specification, or not ADIF-valid | 1,395 |
| Refused by tqsllib as well | 4 |
| Refused by LoTW's own contacted-call validation | 64 |

QG Trust read 1,981,140 QSO records and signed 89,984 QSOs, those within the test certificate's dates.

QG Trust follows the specification: a log that is not in it is refused, with the line and what the
specification requires there, and correcting it is for the person who made the log. tqsllib accepts
many of these logs. Refusals by kind:

| Refusal | Logs |
|---|---:|
| `START-OF-LOG` version is not `2.0` or `3.0` | 1,293 |
| `CONTEST` value outside the specification's characters or length | 48 |
| Text that is not UTF-8 | 30 |
| Band not an ADIF band | 6 |
| QSO line call syntax | 6 |
| QSO before the `CONTEST` line | 4 |
| `CONTEST` line out of order | 2 |
| No received-call field found (a misspelled contest identifier) | 2 |
| Content after `END-OF-LOG` | 1 |
| Mode code not a Cabrillo mode | 1 |
| Non-ASCII QSO line | 1 |
| Field separator | 1 |
| LoTW contacted-call validation (prefix, digits, slashes, length) | 64 |

## What the comparison found and fixed

Each finding was fixed in QG Trust and is held by synthetic regression fixtures; no real log content
is in this repository.

- **QSOs dropped without a refusal.** QSOs whose received call failed LoTW validation were skipped
  silently, and a misplaced `END-OF-LOG` selected the ADI reader, which read nothing. Both now refuse
  the whole log with the line number.
- **Valid logs refused for want of a received call.** IARU HF, ARRL DX CW and SSB, RTTY Roundup,
  International Digital, 10 Meter, 160 Meter and WRTC now have exchanges cited from their sponsors'
  rules: 24 cited entries, 234 guessed.
- **ARRL 160's two layouts.** A W/VE log sends a section and a DX log does not, so the received call
  sits at one of two positions. The position is chosen once per log, by the position that holds a
  plausible call on a strict majority of QSOs; each call then goes to LoTW validation, so a 1×1
  special-event call is signed and an invalid one is refused by line.
- **Contest values the specification refuses** (spaces, punctuation, over 32 characters) are refused;
  every value within the specification takes the decided unknown-contest path.

## Method

- **Sample:** stratified across contest and Cabrillo version, at least 5,000 logs including v2.
- **Reference:** tqsllib 2.8.7 in a container built from its source, run with `--network=none` and
  `--security-opt label=disable`, so read-only mounts work on an SELinux host without relabeling.
  Nothing connects to LoTW.
- **Signer:** the repository's test PKI and a synthetic station. QSOs outside the test certificate's
  dates are read and compared, not signed.
- **Compared:** each reader's records in input order (call, band, mode, UTC date and time, numeric
  frequency), and each signed contact's fields, `SIGNDATA` and signature.
- **Classification:** each refusal carries a fixed reason kind and the physical line, never an input
  value. Specification refusals count as correct; only reader or signing disagreements on accepted
  logs, and refusals that contradict decision 0016, count as `QGT wrong`, which exits nonzero.
- **Public output:** counts only. No calls, header values, file paths, digests or per-log findings.

## Run it

```sh
uv run --no-project python scripts/cabrillo-differential.py --synthetic --qgt-only
uv run --no-project python scripts/cabrillo-differential.py \
  --archive /path/to/public-contest-logs --count 5000 --report /tmp/cabrillo-report.json
```

The default image is `localhost/qgt-tqsllib:2.8.7`; `--image localhost/qgt-tqsllib-asan:2.8.7` runs
the reference under ASan and UBSan. Comparison artifacts are owner-only, outside the repository, and
removed after the run.

## Planted faults

`scripts/test-cabrillo-faults.py` plants each fault, requires a failing test, then restores the source
and requires the test to pass: a refusal message carrying an input value; time normalization removed;
a contest syntax refusal for a valid unknown identifier; conversion failures skipped; a misplaced
end marker read as ADI; a cited exchange reverted to guessed; an ambiguous call accepted; an
off-by-one band edge; a Cabrillo claim retried as ADI; and the every-QSO rule restored for ARRL
160's two positions.
