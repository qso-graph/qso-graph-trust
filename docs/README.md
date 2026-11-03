# QSO Graph Trust: documents

- [decisions/](decisions/): what was decided and why.
  - [0001](decisions/0001-rust-for-the-library.md): Rust for the library and command line, Electron for the app.
  - [0002](decisions/0002-no-c-in-the-library.md): no C or C++ in the library; TLS is the one place C is allowed.
  - [0003](decisions/0003-one-repository.md): the library, the command line and the app live in one repository.
  - [0004](decisions/0004-supply-chain.md): outside crates reviewed with cargo-vet, their sources held by cargo-deny.
- The plan, its phases and their gates: [qso-graph-desktop#169](https://github.com/qso-graph/qso-graph-desktop/issues/169).
