<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Sign a Cabrillo log

Use `qg-trust sign contest.log -l Home` to sign a Cabrillo log with your saved station location.
QG Trust recognizes the format from the file contents. It accepts Cabrillo 2.0 and 3.0 and skips
`X-QSO` records.

If QG Trust refuses the log, the message gives the physical line number and the requirement to
meet. Open the original log in a text editor, correct that line, and run the command again.
The message contains no calls or values copied from your log.

| Requirement | Correction |
|---|---|
| START-OF-LOG must be 2.0 or 3.0 | Export a supported Cabrillo version or correct the version header. |
| Header text must be UTF-8 | Save or export the file with UTF-8 encoding. |
| CONTEST must contain 1 to 32 ASCII letters, digits, or hyphens | Use the contest sponsor's identifier. Remove internal spaces and other punctuation. |
| QSO mode must be one of CW, PH, FM, RY, DG | Correct the mode code using the contest's Cabrillo format. |
| Received exchange must have exactly one call candidate | Correct the exchange layout or export ADIF with an explicit CALL field. |
| No single received-call field fits every QSO | Correct the exchanges on the two QSO lines named in the message, or export ADIF. |

A contest identifier outside ADIF 3.1.8's Contest_ID list is accepted when its syntax is valid
and the same single received-call field fits every QSO. Missing or ambiguous received calls
refuse the whole log before signing. QG Trust follows the format rules even when another reader
accepts the file.
