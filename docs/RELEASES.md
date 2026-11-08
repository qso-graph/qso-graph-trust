<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Releasing QSO Graph Trust

KI7MT starts **Actions → Release → Run workflow** from **main**. Signing and publishing require
that workflow, that branch, KI7MT as both the original and rerun actor, and the exact commit the
workflow run started on. A branch, tag, PR ref, different workflow, automatic event or different
build commit is refused before signing environments are entered.

PR CI and manually started **Binaries** runs produce unsigned test artifacts. Merging publishes
nothing. Signing and publishing are separate stages of Release: every binary must build, sign,
verify and attest successfully before crates or a GitHub release can be published.

## Preparing a release

A release starts with one pull request that:

1. Sets the version in every crate's `Cargo.toml` and in `Cargo.lock`, and turns CHANGELOG's
   `## [Unreleased]` into the version's heading with the date.
2. Refreshes the figures in the README's **Security — Our #1 Priority** section, rounded down so
   they stay true as they grow:
   - the tests: the passed counts from `cargo test --workspace --all-features --locked`, summed;
   - the fuzz inputs: the `Done N runs` lines of the latest CI fuzz job, summed, and the number of
     targets in `fuzz/fuzz_targets/`;
   - the policy checks: the `pass` lines of `cargo xtask policy`.

## One release operation, with a dry run

1. Merge the reviewed change after its CI passes.
2. Start **Release** on **main**, enter the version already in Cargo.toml, and leave **dry_run**
   checked. This builds and signs Windows and macOS programs, obtains Apple notarization, builds
   both Linux programs and attests all four archives. It creates no tag, crate publication or
   GitHub release. Downloadable test artifacts remain on the workflow run.
3. After verifying that run, start **Release** on **main** with the same version and **dry_run**
   unchecked to publish. The workflow repeats validation and signs the exact commit it publishes.

The crates-io environment protects both crate publication and the final GitHub release. Its
branch policy, and those of macos-signing and windows-signing, must allow only the main branch,
with no tag or PR-ref rules. These settings are managed on GitHub; editing YAML cannot establish
them. The tests in scripts/test_release_check.py exercise the source checks, including refused
branches, events, callers, operators and commits.

## Shared project signing identity

Use the existing QSO Graph signing identities. The shared GitHub organization secrets are scoped
to an explicit repository allowlist, initially qso-graph-desktop and qso-graph-trust:

| Platform | Names passed to the signing workflow |
| --- | --- |
| Windows | AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID |
| macOS | CSC_LINK, CSC_KEY_PASSWORD, APPLE_API_KEY_P8, APPLE_API_KEY_ID, APPLE_API_ISSUER, APPLE_TEAM_ID |

The release caller passes these nine names explicitly to binaries.yml. Publication credentials
are not passed. Environment secrets override organization secrets with the same name: retire
old environment copies only after the shared configuration has been verified, or they will hide
future organization-level rotations. No signing value belongs in source, logs or command arguments.

Organization secrets are accessible to eligible workflows in the allowed repositories; an
environment's branch rule does not itself restrict organization-secret access. Therefore each
allowed repository must retain the manual main Release guards, keep CI unsigned, and protect
workflow changes through reviewed pull requests. Adding a repository requires adding it to the
secret allowlist and validating its release workflow; it does not require a new Apple certificate.

Windows uses OIDC. Reusing the three Azure IDs does not grant a new repository permission to sign:
Azure must authorize its subject, for QGT:
`repo:qso-graph/qso-graph-trust:environment:windows-signing`.
The intended account/profile and signature publisher are verified by binaries.yml.

GitHub environments belong to individual repositories. A reusable workflow or an identically
named environment does not retrieve Desktop's stored credentials. Moving the existing values
to the shared organization scope is a one-time provisioning operation; the release workflow
never copies or exports credentials. The credential migration must be completed and a main
Release dry run must pass before publishing 0.1.0.
