# 0007: In QSO Graph Desktop, QG Trust runs inside the credential core

Decided 2026-11-03 by KI7MT, after a review by Codex (gpt-6-astra, high). Settles what decision 0005 left
open: where the library's code loads in QSO Graph Desktop. Desktop's requirements are in its
specification, `QGD-SPEC-001` §3.4 (`QGD-LTW-0001` to `0014`), and are not restated here.

## What was decided

- **QG Trust's library is built into Desktop's credential core** (`callsign.node`, the QG Callsigns
  process), the one holder of credentials Desktop has. There is no second native addon and no new
  process (`QGD-LTW-0001`).
- **Desktop takes the library from this repository, pinned to one of QG Trust's releases** by tag and
  commit, never from a registry or a branch (`QGD-LTW-0001`). A Desktop Release carries a QG Trust
  release (`vX.Y.Z`), and a Desktop Beta or Daily a QG Trust beta (`vX.Y.Z-beta.N`), never mixed;
  Desktop's Release workflow and Daily job refuse anything else (`QGD-LTW-0001.1`).
- **Every QG Trust release and beta is also published on crates.io,** from its tag, for everyone else:
  three crates at one version, `qso-graph-trust` (the library), `qso-graph-trust-awslc` (the binding it
  needs) and `qso-graph-trust-cli` (installed as `qg-trust`). Desktop still pins the tag and commit, so
  it fetches QG Trust one way only; crates.io holds the same commit.
- **The QG Trust extension is JavaScript and holds nothing secret.** It reaches the library only through
  the `lotw:` grants (`QGD-LTW-0002`). The core confirms every act that signs, sends, imports or deletes
  in its own dialog, chooses every file itself, and refuses every request from an extension that is off
  (`QGD-LTW-0003`, `QGD-LTW-0004`, `QGD-APP-0024`).
- **In Desktop, a log signs at a Desktop Location,** which already holds every field a TQSL station
  location does (`QGD-STN-0009`, `QGD-LTW-0008`). Restoring a `.tbk` makes TQSL's locations Desktop
  Locations. The command line keeps its own locations in the library's store.
- **Keys, certificates and the record of QSOs already signed are in one store the library owns,** shared
  by the command line and Desktop (`QGD-LTW-0007`).
- **Backup:** LoTW's data is one encrypted part of Desktop's one backup (`QGD-LTW-0010`, `QGD-LTW-0011`).

## What this asks of the library

- **Releases of its own,** tagged `vX.Y.Z` and `vX.Y.Z-beta.N`, each a commit that passed CI. A tag is
  never moved. QG Trust's release workflow publishes the three crates from the tag with crates.io's
  Trusted Publishing, so no token is stored; the first publish of each crate, before Trusted Publishing
  can be set up, is KI7MT's, with one short-lived token scoped to that crate. The test and policy crates
  are never published.
- **The store** (`QGD-LTW-0007`): the OS credential store service `io.qso-graph.trust`, and
  `io.qso-graph.trust.test` for tests, chosen by the caller, never by default; keys named `key:<uuid>`;
  one versioned file for certificates and the signed-QSO record, written under a lock, replaced whole,
  a key stored before the file names it; orphans reported, never removed; an unknown version refused.
  Its layout is designed with phase 3 (qso-graph-desktop#172).
- **No API returns a key** (`QGD-LTW-0005`). A key is read to sign or to back up, and dropped after.
- **The backup part** (`QGD-LTW-0010`): written and read by the library, so the command line's backup is
  the same. AES-256-GCM and PBKDF2-HMAC-SHA-256 through aws-lc-rs, inside the binding (decision 0006),
  with the format, version and part name authenticated.
- **A station from a Desktop Location** (`QGD-LTW-0008`): the library takes its fields as given and
  checks them as it checks any station.
- **Uploads use the caller's TLS** (`QGD-LTW-0013`): in Desktop, the credential core's. The endpoint is
  fixed in the library.

## What was weighed

- **A process of its own for signing.** It would keep keys apart from the credential core's network
  traffic and contain a crash in signing. Against it: a second holder of credentials, contradicting
  `QGD-CRD-0002`; a new process, broker and build entries; and the same user's other processes could
  still reach it. Decided against; the core's custody is instead made explicit and tested
  (`QGD-LTW-0005`, `QGD-LTW-0006`).
- **Loading the library with the extension.** Not possible: extensions are JavaScript in one shared
  process, and nothing loads native code there.

## Corrected in review

The first draft claimed more than the code shows, and Codex's review found it:

- The wiping allocator covers Rust's memory only, not V8's heap, and wiping cannot protect a key while it
  signs. `QGD-LTW-0006` says exactly that, and the custody test runs against the packaged process.
- Not everything else is FIPS: unlocking a key protected in a file uses RustCrypto. `QGD-LTW-0014` states
  which operation uses which. That both AWS-LC builds are in `callsign.node` is checked on the built
  artifact, not inferred from `cargo tree`.
- A grant marked as needing the operator does not ask the operator each time, so the core confirms each
  act itself (`QGD-LTW-0003`).
- Requests from an extension that is off were not refused; `QGD-APP-0024` closes that for every extension.

## Amended 2026-11-04: how a release is published

What was built differs from the release lines above in two details. The release workflow publishes
two crates, the binding and the library, from main's commit, and tags that commit once both are on
crates.io, so a tag means published. The command line is to be published once it signs, planned for 0.1.0-beta.3.
How to release: AGENTS.md, Releasing.
