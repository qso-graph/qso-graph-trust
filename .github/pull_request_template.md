## Issues

Closes #

## What changed

## Verification

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`: PASS
- [ ] `cargo xtask policy`: PASS (no C in the library, no unsafe code outside the AWS-LC binding)
- [ ] A new check or gate is proved by a planted case that fails it

## Credentials

- [ ] No real certificate, private key, password, token or real QSO log appears in this PR, its tests, or its evidence.
