# QSO Graph Trust: documents

- [decisions/](decisions/): what was decided and why.
  - [0001](decisions/0001-rust-for-the-library.md): Rust for the library and command line (its app superseded by 0005).
  - [0002](decisions/0002-no-c-in-the-library.md): no C or C++ in the library but its named providers (amended; signing decided again in 0006).
  - [0003](decisions/0003-one-repository.md): the library and the command line live in one repository (its app superseded by 0005).
  - [0004](decisions/0004-supply-chain.md): outside crates reviewed with cargo-vet, their sources held by cargo-deny.
  - [0005](decisions/0005-qso-graph-desktop-is-the-interface.md): no QGT app; QSO Graph Desktop is the interface, with QG Trust as an extension.
  - [0006](decisions/0006-aws-lc-signs.md): AWS-LC signs LoTW's signature, through one binding, the only crate with unsafe code.
  - [0007](decisions/0007-inside-the-credential-core.md): in QSO Graph Desktop, QG Trust runs inside the credential core; every release and beta also goes to crates.io.
- [FEATURE-PARITY.md](FEATURE-PARITY.md): every TQSL 2.8.7 feature and option, app and command line,
  with QG Trust's status and the decision on each.
- The plan, its phases and their gates: [qso-graph-desktop#169](https://github.com/qso-graph/qso-graph-desktop/issues/169).
