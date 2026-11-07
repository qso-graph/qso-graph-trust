// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The repository's policy checks, run by `cargo xtask policy` and by CI.
//!
//! - **No C in the library** (docs/decisions/0002-no-c-in-the-library.md): nothing
//!   in the dependency tree of [`PROTECTED`], with every feature on and on every
//!   platform, links a native library or depends on a crate that builds native
//!   code; and every build script or procedural macro in that tree, which could
//!   run a compiler itself, is one reviewed by exact name and version.
//! - **No unsafe code** (AGENTS.md): the workspace forbids `unsafe_code`, every
//!   member takes the workspace's lints, and every crate root says
//!   `#![forbid(unsafe_code)]` where the compiler reads it.
//! - **No networking in the library's workspace dependency graph**: every source
//!   file is read as tokens, whatever its cfg; the caller supplies upload's TLS
//!   connection. The binding may use only [`BINDING_AWS_LC_ALLOWED`].
//!
//! - **No key data in freed memory** (AGENTS.md): every program
//!   a workspace crate builds (a binary, or a library another language loads)
//!   installs [`WIPING_ALLOCATOR`], so every block is wiped when it is freed,
//!   whichever library allocated it.
//!
//! - **In a consumer's build** (`cargo xtask consumer <Cargo.toml>`, run from a release's
//!   checkout by a program that builds the library in, such as QSO Graph Desktop): the library
//!   is that release from [`REPOSITORY`] ([`consumer_source`]), everything it needs is the
//!   version this repository's lock file holds ([`consumer_versions`]), it brings no C but
//!   AWS-LC's, with AWS-LC's FIPS build accepted only as the consumer's ([`consumer_no_c`]), and
//!   every program the consumer builds wipes what it frees.
//!
//! Each check is proved by planted cases it must catch (tests/planted.rs), and
//! anything a check cannot read counts as a failure, never a pass.

#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The crates that hold the key, the signing and the file parsers.
pub const PROTECTED: &[&str] = &["qso-graph-trust"];

/// The crates QGT ships. Every crate they take from outside the workspace is
/// reviewed by exact name and version through cargo-vet, because one could hand
/// them a macro that writes unsafe code into our own source (found in
/// review: `paste!` can build the keyword from pieces). The no-C rules are the
/// library's alone: the command line (`qso-graph-trust-cli`) carries the TLS stack, which is C (docs/decisions/0002).
pub const SHIPPED: &[&str] = &[
    "qso-graph-trust",
    "qso-graph-trust-awslc",
    "qso-graph-trust-cli",
];

/// The one cryptographic provider whose C the library may build: AWS-LC, which QSO Graph Desktop
/// already ships (docs/decisions/0006), as its C (`aws-lc-sys`, for LoTW's
/// RSA-SHA-1 signature, which the safe API does not make) and its safe API (`aws-lc-rs`, for the
/// operations it offers, as AGENTS.md requires: certificate signature checks). One may depend on the
/// other; any other crate only through the binding. Their own files and build are not scanned;
/// everything they depend on still is.
pub const CRYPTO_PROVIDERS: &[&str] = &["aws-lc-sys", "aws-lc-rs"];

/// A separate pure-Rust provider exception, NOT a native-code exemption: Secret Service's
/// Desktop-default crypto-rust session transport only (DH, HKDF/SHA-256, AES-CBC).
/// Its sources remain scanned. No signing, certificate, TLS or other use is permitted.
pub const SECRET_SERVICE_PROVIDER: (&str, &str) = ("secret-service", "5.2.0");

/// Exact incoming edges for that provider's algorithms and DH arithmetic. These versions cannot
/// be used directly by a signer, certificate handler, TLS stack or another shipped crate.
const SECRET_SERVICE_CRYPTO_EDGES: &[(&str, &str, &str, &str)] = &[
    ("secret-service", "5.2.0", "aes", "0.9.4"),
    ("secret-service", "5.2.0", "cbc", "0.2.1"),
    ("secret-service", "5.2.0", "hkdf", "0.13.0"),
    ("secret-service", "5.2.0", "sha2", "0.11.1"),
    ("secret-service", "5.2.0", "num", "0.4.3"),
    ("hkdf", "0.13.0", "hmac", "0.13.0"),
    ("num", "0.4.3", "num-bigint", "0.4.8"),
    ("num-rational", "0.4.2", "num-bigint", "0.4.8"),
];

/// The one workspace crate allowed unsafe code, and the only one that may depend on a
/// [`CRYPTO_PROVIDERS`] crate: QG Trust's binding to AWS-LC. Instead of the workspace's lints it must
/// carry exactly [`BINDING_LINTS`] (docs/decisions/0006).
pub const UNSAFE_BINDING: &str = "qso-graph-trust-awslc";

/// AWS-LC's entire raw API surface used by the binding, including types and
/// constants. Adding an item requires reviewing its purpose here; socket BIOs
/// and other provider APIs are refused even when Rust's networking is absent.
pub const BINDING_AWS_LC_ALLOWED: &[&str] = &[
    "BIGNUM",                  // integers
    "BN_CTX_free",             // cleanup
    "BN_CTX_new",              // allocation
    "BN_cmp",                  // comparison
    "BN_free",                 // cleanup
    "BN_is_word",              // exponent
    "BN_new",                  // allocation
    "BN_num_bits",             // sizing
    "BN_primality_test",       // primality
    "BN_set_word",             // exponent
    "CBB",                     // marshalling
    "CBB_cleanup",             // cleanup
    "CBB_init_fixed",          // marshalling
    "CBB_len",                 // sizing
    "CBS",                     // parsing
    "CBS_init",                // parsing
    "EVP_PKEY",                // keys
    "EVP_PKEY_free",           // cleanup
    "EVP_PKEY_get1_RSA",       // extraction
    "EVP_PKEY_new",            // allocation
    "EVP_PKEY_set1_RSA",       // assignment
    "EVP_marshal_private_key", // marshalling
    "EVP_marshal_public_key",  // marshalling
    "EVP_parse_private_key",   // parsing
    "EVP_parse_public_key",    // parsing
    "NID_sha1",                // signing
    "NID_sha256",              // signing
    "RSA",                     // keys
    "RSA_bits",                // sizing
    "RSA_free",                // cleanup
    "RSA_generate_key_ex",     // generation
    "RSA_get0_e",              // exponent
    "RSA_get0_factors",        // factors
    "RSA_get0_n",              // modulus
    "RSA_new",                 // allocation
    "RSA_sign",                // signing
    "RSA_size",                // sizing
    "SHA1",                    // hashing
];

/// The binding's own lints, exactly: unsafe denied unless allowed block by block, unsafe operations
/// marked even inside unsafe functions, every unsafe block documented with its SAFETY reason, one
/// unsafe operation per block.
pub const BINDING_LINTS: &str = r#"[rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"
missing_docs = "warn"

[clippy]
undocumented_unsafe_blocks = "deny"
multiple_unsafe_ops_per_block = "deny"
"#;

/// The global allocator every QG Trust program installs, exactly as written:
/// 1Password's `zeroizing-alloc` over the system allocator, which wipes each block
/// as it is freed (AGENTS.md; reviewed in supply-chain/audits.toml). The paths are
/// absolute, so they name the outside crates and never a local module of the same
/// name (found in review: a local `mod zeroizing_alloc` made the line install
/// the plain system allocator).
pub const WIPING_ALLOCATOR: &str = "::zeroizing_alloc::ZeroAlloc<::std::alloc::System>";

/// The crate [`WIPING_ALLOCATOR`] names, as every program's package must depend on it:
/// from crates.io, at exactly this version, by its own name.
pub const WIPING_ALLOCATOR_CRATE: (&str, &str) = ("zeroizing-alloc", "=0.1.1");

/// The one program allowed to go without it: the custody test's control, which
/// proves the test finds what an unwiped free leaves behind. Named by its package,
/// which must be unpublished, its binary and its root, so no other program can
/// borrow the exception (found in review).
pub const UNWIPED_CONTROL: (&str, &str, &str) = (
    "qso-graph-trust-custody",
    "qgt-custody-unwiped",
    "crates/qso-graph-trust-custody/src/bin/qgt-custody-unwiped.rs",
);

/// Whether a crate is the named cryptographic provider.
fn crypto_provider(name: &str) -> bool {
    CRYPTO_PROVIDERS.contains(&name)
}

/// Where a shipped crate's dependencies come from, for what this workspace builds
/// and what a consumer of the published crates builds: crates.io only, no
/// dependency named by both a path and a version except our own shipped crates,
/// no other registry, and no unreviewed build script or procedural macro in our
/// own crates. Reviewing outside crates is cargo-vet's. Sorted; empty passes.
pub fn unreviewed_in(meta: &Value, shipped: &[&str]) -> Vec<String> {
    unreviewed_reviewing(meta, shipped, REVIEWED)
}

fn unreviewed_reviewing(
    meta: &Value,
    shipped: &[&str],
    list: &[(&str, &str, &str)],
) -> Vec<String> {
    let empty = Vec::new();
    let packages: HashMap<&str, &Value> = meta["packages"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes: HashMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let workspace = members(meta);
    let mut problems = Vec::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for want in shipped {
        let found: Vec<&str> = packages
            .iter()
            .filter(|(id, p)| p["name"].as_str() == Some(want) && workspace.contains(*id))
            .map(|(id, _)| *id)
            .collect();
        if found.is_empty() {
            problems.push(format!("shipped crate {want} is not a workspace member"));
        }
        queue.extend(found);
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let pkg = packages.get(id);
        let name = pkg.and_then(|p| p["name"].as_str()).unwrap_or(id);
        let version = pkg.and_then(|p| p["version"].as_str()).unwrap_or("?");
        let is_reviewed = list.iter().any(|(n, v, _)| *n == name && *v == version);
        if name == SECRET_SERVICE_PROVIDER.0 {
            let features = nodes.get(id).and_then(|n| n["features"].as_array());
            if version != SECRET_SERVICE_PROVIDER.1
                || !features.is_some_and(|f| f.len() == 1 && f[0] == "crypto-rust")
            {
                problems.push(format!(
                    "{name} {version}: only 5.2.0 crypto-rust session transport is allowed"
                ));
            }
        }
        // What a consumer of the published crate builds, not only what this
        // workspace builds: a dependency naming both a path and a version builds
        // the path here but the registry's crate of that name once published, and
        // another registry is another source (found in review). Only our own
        // shipped crates may be named both ways, since their published form is ours.
        for dep in pkg
            .and_then(|p| p["dependencies"].as_array())
            .unwrap_or(&empty)
        {
            let dep_name = dep["name"].as_str().unwrap_or("?");
            let both = dep["path"].is_string() && dep["req"].as_str().is_some_and(|r| r != "*");
            if both && !shipped.contains(&dep_name) {
                problems.push(format!(
                    "{name} depends on {dep_name} by both a path and a version: published, it would build the registry's"
                ));
            }
            if !dep["registry"].is_null() {
                problems.push(format!(
                    "{name} depends on {dep_name} from another registry"
                ));
            }
        }
        // The repository's tooling never ships: its dependencies are held only to
        // safe-to-run, so it may not be in a shipped crate's graph (found in
        // review).
        if name == "xtask" {
            problems.push("xtask is in a shipped crate's dependencies".to_string());
        }
        // Outside crates come from crates.io; reviewing them is cargo-vet's,
        // which CI runs beside this.
        if !workspace.contains(id) && pkg.and_then(|p| p["source"].as_str()) != Some(CRATES_IO) {
            problems.push(format!("{name} {version} is not a crates.io crate"));
        }
        // A build script or procedural macro anywhere a shipped crate reaches, our
        // own included, is reviewed too: a build script can compile a hidden crate
        // and hand the shipped crate its search path, outside Cargo's graph (found
        // in review).
        for target in pkg.and_then(|p| p["targets"].as_array()).unwrap_or(&empty) {
            let kinds = target["kind"].as_array().unwrap_or(&empty);
            for (kind, what) in [
                ("custom-build", "a build script"),
                ("proc-macro", "a procedural macro"),
            ] {
                if kinds.iter().any(|k| k == kind) && workspace.contains(id) && !is_reviewed {
                    problems.push(format!(
                        "{name} {version} has {what} that has not been reviewed"
                    ));
                }
            }
        }
        for dep in nodes
            .get(id)
            .and_then(|n| n["deps"].as_array())
            .unwrap_or(&empty)
        {
            let shipped_kind = dep["dep_kinds"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .any(|k| k["kind"].is_null() || k["kind"] == "build");
            if shipped_kind && let Some(d) = dep["pkg"].as_str() {
                if let Some(child) = packages.get(d) {
                    let child_name = child["name"].as_str().unwrap_or("?");
                    let child_version = child["version"].as_str().unwrap_or("?");
                    if child_name == SECRET_SERVICE_PROVIDER.0 {
                        let approved_caller = name == "qso-graph-trust"
                            || (name == "zbus-secret-service-keyring-store" && version == "1.0.1");
                        if !approved_caller {
                            problems.push(format!("{name} {version} uses Secret Service outside the credential backend"));
                        }
                        if workspace.contains(id)
                            && pkg.is_some_and(|p| {
                                p["dependencies"].as_array().into_iter().flatten().any(|d| {
                                    d["name"] == "secret-service" && !d["rename"].is_null()
                                })
                            })
                        {
                            problems.push(format!(
                                "{name} renames secret-service outside the checked transport API"
                            ));
                        }
                    }
                    let restricted = SECRET_SERVICE_CRYPTO_EDGES.iter().any(|(n, v, cn, cv)| {
                        (*n == name && *v == version && *cn == child_name)
                            || (*cn == child_name && *cv == child_version)
                    });
                    if restricted
                        && !SECRET_SERVICE_CRYPTO_EDGES.contains(&(
                            name,
                            version,
                            child_name,
                            child_version,
                        ))
                    {
                        problems.push(format!("{name} {version} uses {child_name} {child_version} outside Secret Service session transport"));
                    }
                }
                queue.push_back(d);
            }
        }
    }
    problems.sort();
    problems.dedup();
    problems
}

/// Crates whose only job is to compile or find native code for a build script.
const NATIVE_BUILD: &[&str] = &[
    "autotools",
    "bindgen",
    "cc",
    "cmake",
    "cxx-build",
    "nasm-rs",
    "pkg-config",
    "vcpkg",
];

/// Crates that only bind the operating system's own interfaces: the C library,
/// the Windows API and its import libraries, Apple's frameworks, and the OS's
/// random-number source. They declare foreign functions and, for Windows, ship
/// import libraries, because that is how any program calls the OS; they compile
/// and ship no C, C++ or assembly. A named category: allowed, and reviewed by exact version
/// through cargo-vet like every outside crate (docs/decisions/0002).
pub const OS_BINDINGS: &[&str] = &[
    "core-foundation",
    "core-foundation-sys",
    "errno",
    "getrandom",
    "libc",
    "linux-raw-sys",
    "rustix",
    "security-framework",
    "security-framework-sys",
    "windows-link",
    "windows-sys",
    "windows-targets",
    "windows_aarch64_gnullvm",
    "windows_aarch64_msvc",
    "windows_i686_gnu",
    "windows_i686_gnullvm",
    "windows_i686_msvc",
    "windows_x86_64_gnu",
    "windows_x86_64_gnullvm",
    "windows_x86_64_msvc",
];

/// Foreign declarations read individually in crates that are not OS bindings. Only this
/// finding in this file at this exact version is allowed; native links and source still fail.
/// These crates remain subject to cargo-vet, like every outside crate.
pub const FOREIGN_DECLARATIONS: &[(&str, &str, &str, &str)] = &[
    (
        "zbus",
        "5.19.0",
        "src/fdo/peer.rs",
        "macOS gethostuuid, from the OS, supplies the D-Bus machine identifier",
    ),
    (
        "uuid",
        "1.29.0",
        "src/rng.rs",
        "wasm-bindgen imports JavaScript crypto.getRandomValues; not built on shipping targets",
    ),
    (
        "uuid",
        "1.29.0",
        "src/timestamp.rs",
        "wasm-bindgen imports JavaScript Date.now; not built on shipping targets",
    ),
];

fn reviewed_foreign_declaration(name: &str, version: &str, finding: &str) -> bool {
    FOREIGN_DECLARATIONS.iter().any(|(n, v, file, _)| {
        name == *n
            && version == *v
            && finding.strip_suffix(" declares foreign functions") == Some(*file)
    })
}

/// The platforms QGT ships for. The no-C check reads each one's dependency tree,
/// and no other: code for platforms QGT never builds is not shipped.
pub const SHIPPING_TARGETS: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
];

/// Build scripts and procedural macros of the workspace's own crates, each by
/// name and version, read and found to compile nothing. None today. Outside
/// crates are reviewed through cargo-vet instead.
const REVIEWED: &[(&str, &str, &str)] = &[];

/// The one registry an outside crate may come from.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Native source and object code, by file extension: refused in every crate.
const NATIVE_SOURCE: &[&str] = &[
    "asm", "c", "cc", "cpp", "cxx", "dll", "dylib", "h", "hpp", "o", "obj", "s", "so",
];

/// Import libraries, which only an OS-binding crate may carry.
const IMPORT_LIBRARIES: &[&str] = &["a", "lib"];

/// `cargo metadata` for every platform and every feature, of the workspace at
/// `manifest`, from its committed lockfile: a native dependency behind a feature
/// nobody enables by default is still one a user can switch on (found in
/// review).
pub fn metadata(manifest: &Path) -> Result<Value, String> {
    metadata_for(manifest, None)
}

/// [`metadata`], limited to one target platform's dependency tree when given.
pub fn metadata_for(manifest: &Path, target: Option<&str>) -> Result<Value, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = Command::new(cargo);
    command.args([
        "metadata",
        "--format-version",
        "1",
        "--all-features",
        "--locked",
        "--manifest-path",
    ]);
    command.arg(manifest);
    if let Some(target) = target {
        command.args(["--filter-platform", target]);
    }
    let out = command
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("cargo metadata is not JSON: {e}"))
}

fn os_binding(name: &str) -> bool {
    OS_BINDINGS.contains(&name)
}

fn members(meta: &Value) -> BTreeSet<&str> {
    meta["workspace_members"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Every reason something the protected crates need to build and run (normal and
/// build dependencies; never dev-dependencies, which only the tests use) brings
/// native code, sorted. Empty means the check passes.
pub fn no_c(meta: &Value, protected: &[&str]) -> Vec<String> {
    no_c_reviewing(meta, protected, REVIEWED, None)
}

/// [`no_c_reviewing`] in a consumer's build (see [`consumer_no_c`]): our crates are the
/// consumer's dependencies from [`REPOSITORY`], and AWS-LC's FIPS build is the provider's when
/// the consumer turns it on.
struct InConsumer {
    fips: bool,
}

/// [`no_c`] with the reviewed list given, so tests can name their own.
fn no_c_reviewing(
    meta: &Value,
    protected: &[&str],
    list: &[(&str, &str, &str)],
    consumer: Option<&InConsumer>,
) -> Vec<String> {
    let reviewed =
        |name: &str, version: &str| list.iter().any(|(n, v, _)| *n == name && *v == version);
    let empty = Vec::new();
    let packages: HashMap<&str, &Value> = meta["packages"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes: HashMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let field = |id: &str, f: &str| {
        packages
            .get(id)
            .and_then(|p| p[f].as_str())
            .unwrap_or(id)
            .to_string()
    };
    let workspace = members(meta);
    // Our own crates: the workspace's, or in a consumer's build those it takes from our repository.
    let ours = |id: &str| match consumer {
        None => workspace.contains(id),
        Some(_) => packages
            .get(id)
            .is_some_and(|p| from_repository(p) && SHIPPED.iter().any(|s| p["name"] == *s)),
    };
    let fips = consumer.is_some_and(|c| c.fips);
    let provider = |name: &str| crypto_provider(name) || (fips && name == FIPS_PROVIDER);
    let output_dir: Vec<PathBuf> = meta["target_directory"]
        .as_str()
        .and_then(|t| std::fs::canonicalize(t).ok())
        .into_iter()
        .collect();

    let mut problems = Vec::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for want in protected {
        let found: Vec<&str> = packages
            .iter()
            .filter(|(_, p)| p["name"].as_str() == Some(want))
            .map(|(id, _)| *id)
            .collect();
        // A renamed or missing crate must fail, or the check passes by checking
        // nothing; and one moved out of the workspace would escape the unsafe check
        // (found in review).
        if found.is_empty() {
            problems.push(format!("protected crate {want} is not in this workspace"));
        }
        for id in &found {
            if consumer.is_none() && !workspace.contains(id) {
                problems.push(format!("protected crate {want} is not a workspace member"));
            }
            if consumer.is_some() && !ours(id) {
                problems.push(format!("protected crate {want} is not from {REPOSITORY}"));
            }
        }
        queue.extend(found);
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let (name, version) = (field(id, "name"), field(id, "version"));
        let pkg = packages.get(id);
        if let Some(links) = pkg.and_then(|p| p["links"].as_str())
            && !os_binding(&name)
            && !provider(&name)
        {
            problems.push(format!("{name} links the native library {links}"));
        }
        if !ours(id) && pkg.and_then(|p| p["source"].as_str()) != Some(CRATES_IO) {
            problems.push(format!("{name} {version} is not a crates.io crate"));
        }
        if let Some(dir) = pkg
            .and_then(|p| p["manifest_path"].as_str())
            .and_then(|m| Path::new(m).parent())
        {
            // A target's source outside its crate's directory would be outside the
            // search below (found in review).
            for target in pkg.and_then(|p| p["targets"].as_array()).unwrap_or(&empty) {
                // Compared canonically: Cargo reports `crate/../elsewhere/lib.rs`
                // as written, which starts with `crate` lexically. A path that
                // cannot be resolved counts as outside.
                if let Some(src) = target["src_path"].as_str()
                    && !within(Path::new(src), dir)
                {
                    problems.push(format!(
                        "{name} {version}: a target's source is outside the crate: {src}"
                    ));
                }
            }
            // Rust's own `asm!` is allowed in a reviewed outside crate:
            // zeroize's empty barrier, which keeps a key's wiping from
            // being optimized away, is one. In our own crates it stays refused, by
            // the compiler and by the token scan.
            let outside = !ours(id);
            let scanned = if provider(&name) {
                Vec::new()
            } else {
                native_in(dir, &output_dir, os_binding(&name))
            };
            for found in scanned {
                if outside && found.ends_with(" holds assembly") {
                    continue;
                }
                if outside && reviewed_foreign_declaration(&name, &version, &found) {
                    continue;
                }
                problems.push(format!("{name} {version}: {found}"));
            }
        }
        for target in pkg.and_then(|p| p["targets"].as_array()).unwrap_or(&empty) {
            let kinds = target["kind"].as_array().unwrap_or(&empty);
            for (kind, what) in [
                ("custom-build", "a build script"),
                ("proc-macro", "a procedural macro"),
            ] {
                // Our own crates' only: outside crates' are reviewed with the rest
                // of them, through cargo-vet.
                if kinds.iter().any(|k| k == kind) && ours(id) && !reviewed(&name, &version) {
                    problems.push(format!(
                        "{name} {version} has {what} that has not been reviewed"
                    ));
                }
            }
        }
        let deps = nodes
            .get(id)
            .and_then(|n| n["deps"].as_array())
            .unwrap_or(&empty);
        for dep in deps {
            let kinds = dep["dep_kinds"].as_array().unwrap_or(&empty);
            let shipped = kinds
                .iter()
                .any(|k| k["kind"].is_null() || k["kind"] == "build");
            if !shipped {
                continue;
            }
            let Some(dep_id) = dep["pkg"].as_str() else {
                continue;
            };
            // The provider's build tools (cc, cmake and theirs) compile AWS-LC and never ship; what
            // the provider needs at run time is still followed.
            let build_only = kinds.iter().all(|k| k["kind"] == "build");
            if provider(&name) && build_only {
                continue;
            }
            let dep_name = field(dep_id, "name");
            // Only the binding may depend on the provider, so no other crate reaches AWS-LC's C.
            if provider(&dep_name) && name != UNSAFE_BINDING && !provider(&name) {
                problems.push(format!(
                    "{name} depends on {dep_name}: only {UNSAFE_BINDING} may"
                ));
            }
            // The FIPS build only under the safe API whose feature the consumer turned on.
            if fips && dep_name == FIPS_PROVIDER && name != "aws-lc-rs" {
                problems.push(format!(
                    "{name} depends on {FIPS_PROVIDER}: only aws-lc-rs may"
                ));
            }
            if NATIVE_BUILD.contains(&dep_name.as_str()) && !provider(&name) {
                problems.push(format!("{name} builds native code through {dep_name}"));
            }
            queue.push_back(dep_id);
        }
    }
    problems.sort();
    problems.dedup();
    problems
}

/// Where QG Trust's releases are taken from by a program that builds them in: by git, at a
/// release tag and its commit (QSO Graph Desktop's `QGD-LTW-0001`).
pub const REPOSITORY: &str = "https://github.com/qso-graph/qso-graph-trust";

/// AWS-LC's FIPS build. Never this workspace's: QSO Graph Desktop's, for its TLS and its backup's
/// encryption (`QGD-LTW-0014`). In a consumer's build it is accepted as the provider's only when the
/// consumer itself turns on aws-lc-rs's `fips` feature, and only under aws-lc-rs.
pub const FIPS_PROVIDER: &str = "aws-lc-fips-sys";

/// The crates a consumer takes from [`REPOSITORY`] to build the library in.
const CONSUMED: &[&str] = &["qso-graph-trust", "qso-graph-trust-awslc"];

/// Whether a package comes from [`REPOSITORY`] by git.
fn from_repository(package: &Value) -> bool {
    package["source"]
        .as_str()
        .and_then(|s| s.strip_prefix("git+"))
        .and_then(|s| s.strip_prefix(REPOSITORY))
        .is_some_and(|rest| rest.starts_with('?'))
}

/// Whether one of the consumer's own crates turns on aws-lc-rs's `fips` feature.
pub fn consumer_turns_on_fips(meta: &Value) -> bool {
    let workspace = members(meta);
    meta["packages"].as_array().into_iter().flatten().any(|p| {
        p["id"].as_str().is_some_and(|id| workspace.contains(id))
            && p["dependencies"].as_array().into_iter().flatten().any(|d| {
                d["name"] == "aws-lc-rs"
                    && d["kind"].is_null()
                    && d["features"]
                        .as_array()
                        .is_some_and(|f| f.iter().any(|f| f == "fips"))
            })
    })
}

/// A consumer's build of the library: each crate of [`CONSUMED`] is in it once, from
/// [`REPOSITORY`] at the tag of its own version and at `commit`, the commit this check runs from.
/// Sorted; empty passes.
pub fn consumer_source(meta: &Value, commit: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for want in CONSUMED {
        let found: Vec<&Value> = meta["packages"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|p| p["name"] == *want)
            .collect();
        let [package] = found[..] else {
            problems.push(format!(
                "{want} is in the build {} times, not once",
                found.len()
            ));
            continue;
        };
        let version = package["version"].as_str().unwrap_or("?");
        let expected = format!("git+{REPOSITORY}?tag=v{version}#{commit}");
        match package["source"].as_str() {
            Some(source) if source == expected => {}
            source => problems.push(format!(
                "{want} {version} is from {}, not {expected}",
                source.unwrap_or("this workspace")
            )),
        }
    }
    problems.sort();
    problems
}

/// What the library needs to build and run in a consumer's build (normal and build edges, as
/// [`no_c`] follows them; the provider's build tools are AWS-LC's, not the library's) is each the
/// exact version this repository's lock file holds, so what is built is what was reviewed. The
/// consumer's lock file resolves the library's dependencies itself, and can resolve them older or
/// newer. AWS-LC's FIPS build, when the consumer turns it on, is the consumer's and not checked here.
/// Sorted; empty passes.
pub fn consumer_versions(meta: &Value, reviewed: &BTreeSet<(String, String)>) -> Vec<String> {
    let fips = consumer_turns_on_fips(meta);
    let packages: HashMap<&str, &Value> = meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes: HashMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let field = |id: &str, f: &str| {
        packages
            .get(id)
            .and_then(|p| p[f].as_str())
            .unwrap_or("?")
            .to_string()
    };
    let mut problems = Vec::new();
    let mut queue: VecDeque<&str> = packages
        .iter()
        .filter(|(_, p)| p["name"] == PROTECTED[0])
        .map(|(id, _)| *id)
        .collect();
    if queue.is_empty() {
        problems.push(format!("{} is not in the build", PROTECTED[0]));
    }
    let mut seen = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let (n, v) = (field(id, "name"), field(id, "version"));
        let n = n.as_str();
        if fips && n == FIPS_PROVIDER {
            continue;
        }
        if !reviewed.contains(&(n.to_string(), v.clone())) {
            problems.push(format!(
                "{n} {v} is not the version QG Trust's lock file holds"
            ));
        }
        let Some(node) = nodes.get(id) else {
            problems.push(format!("{n} {v} has no dependency node"));
            continue;
        };
        for dep in node["deps"].as_array().into_iter().flatten() {
            let kinds = dep["dep_kinds"].as_array().into_iter().flatten();
            let kinds: Vec<&Value> = kinds.collect();
            if !kinds
                .iter()
                .any(|k| k["kind"].is_null() || k["kind"] == "build")
            {
                continue;
            }
            if crypto_provider(n) && kinds.iter().all(|k| k["kind"] == "build") {
                continue;
            }
            if let Some(dep_id) = dep["pkg"].as_str() {
                queue.push_back(dep_id);
            }
        }
    }
    problems.sort();
    problems.dedup();
    problems
}

/// [`no_c`] in a consumer's build: the library and everything it needs, as the consumer resolves
/// them, bring no native code but AWS-LC's, the FIPS build accepted only as [`FIPS_PROVIDER`] says.
pub fn consumer_no_c(meta: &Value) -> Vec<String> {
    let consumer = InConsumer {
        fips: consumer_turns_on_fips(meta),
    };
    no_c_reviewing(meta, PROTECTED, REVIEWED, Some(&consumer))
}

/// The `(name, version)` of every package in a lock file.
pub fn locked(lock: &Path) -> Result<BTreeSet<(String, String)>, String> {
    let table = read_toml(lock)?;
    let packages = table
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{} has no packages", lock.display()))?;
    packages
        .iter()
        .map(|p| {
            let field = |f: &str| p.get(f).and_then(toml::Value::as_str).map(str::to_string);
            field("name")
                .zip(field("version"))
                .ok_or_else(|| format!("{} has a package with no name or version", lock.display()))
        })
        .collect()
}

/// What in a token stream links native code or holds assembly: a foreign block
/// (`extern "ABI" { ... }`, `extern { ... }`), a `#[link]`, `#[link_name]` or
/// `#[link_section]` attribute, and the assembly macros. A function with a foreign
/// ABI (`extern "C" fn`) is not a binding, and words in strings never count.
pub fn native_tokens(tokens: proc_macro2::TokenStream) -> Vec<&'static str> {
    use proc_macro2::{Delimiter, TokenTree};
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut found = Vec::new();
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Ident(id) => {
                // `r#extern` is an identifier, never the keyword, so the keyword
                // is matched as spelled; `r#asm` is still the macro `asm`
                // (found in review).
                let keyword = id.to_string();
                let name = keyword.strip_prefix("r#").unwrap_or(&keyword);
                let next = trees.get(i + 1);
                let after = trees.get(i + 2);
                let brace = |t: Option<&TokenTree>| matches!(t, Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace);
                // `extern "Rust" { ... }` declares Rust functions, not native ones
                // (found by measuring: zerocopy has one).
                let rust_abi =
                    matches!(next, Some(TokenTree::Literal(l)) if l.to_string() == "\"Rust\"");
                if keyword == "extern"
                    && !rust_abi
                    && (brace(next) || matches!(next, Some(TokenTree::Literal(_))) && brace(after))
                {
                    found.push("declares foreign functions");
                }
                let bang = matches!(next, Some(TokenTree::Punct(p)) if p.as_char() == '!');
                if bang && matches!(name, "asm" | "global_asm" | "naked_asm") {
                    found.push("holds assembly");
                }
            }
            TokenTree::Group(g) => {
                // An attribute is `#[...]` or `#![...]`: a `!` alone is a macro
                // call, as in `assert![link]` (found in review).
                let punct = |k: usize, c: char| matches!(trees.get(k), Some(TokenTree::Punct(p)) if p.as_char() == c);
                let after_hash =
                    i > 0 && (punct(i - 1, '#') || i > 1 && punct(i - 1, '!') && punct(i - 2, '#'));
                let first = g.stream().into_iter().next();
                if after_hash
                    && g.delimiter() == Delimiter::Bracket
                    && matches!(&first, Some(TokenTree::Ident(id))
                        if matches!(id.to_string().trim_start_matches("r#"), "link" | "link_name" | "link_section"))
                {
                    found.push("has a #[link] attribute");
                }
                found.extend(native_tokens(g.stream()));
            }
            _ => {}
        }
    }
    found
}

/// Whether `path` is inside `dir`, both resolved by the file system (`..` and
/// links followed). One that cannot be resolved is not inside.
fn within(path: &Path, dir: &Path) -> bool {
    match (std::fs::canonicalize(path), std::fs::canonicalize(dir)) {
        (Ok(p), Ok(d)) => p.starts_with(d),
        _ => false,
    }
}

/// Every file under a crate's directory that links native code, declares foreign
/// functions, holds assembly or is native code itself, as "path what", with the
/// path relative to the crate and '/'-separated. A directory it cannot read is a
/// finding, never a pass. Symbolic links are not followed, since one could point
/// anywhere, and are findings themselves: a crate from crates.io never has one.
fn native_in(dir: &Path, skip: &[PathBuf], os_binding: bool) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(e) => {
                found.push(format!("{} cannot be read: {e}", d.display()));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    found.push(format!(
                        "{} has an entry that cannot be read: {e}",
                        d.display()
                    ));
                    continue;
                }
            };
            let path = entry.path();
            let rel = path
                .strip_prefix(dir)
                .unwrap_or(&path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let kind = match entry.file_type() {
                Ok(k) => k,
                Err(e) => {
                    found.push(format!("{rel} cannot be read: {e}"));
                    continue;
                }
            };
            if kind.is_symlink() {
                found.push(format!("{rel} is a symbolic link"));
                continue;
            }
            if kind.is_dir() {
                let output = std::fs::canonicalize(&path).is_ok_and(|c| skip.contains(&c));
                if rel != ".git" && !output {
                    stack.push(path);
                }
                continue;
            }
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            // Native source anywhere; import libraries only in an OS binding.
            let native = NATIVE_SOURCE.contains(&ext.as_str())
                || IMPORT_LIBRARIES.contains(&ext.as_str()) && !os_binding;
            if native {
                found.push(format!("{rel} is native code"));
            } else if ext == "rs" && !os_binding {
                // Read as Rust tokens, not text: syn's parser naming `extern "C"`
                // in a string is not a binding (found in review).
                match std::fs::read_to_string(&path) {
                    Ok(text) => match text.parse::<proc_macro2::TokenStream>() {
                        Ok(tokens) => {
                            for what in native_tokens(tokens) {
                                found.push(format!("{rel} {what}"));
                            }
                        }
                        Err(e) => found.push(format!("{rel} does not tokenize as Rust: {e}")),
                    },
                    Err(e) => found.push(format!("{rel} cannot be read as UTF-8 text: {e}")),
                }
            }
        }
    }
    found
}

/// Directories belonging to other packages or Cargo's output, shared by the
/// source-token checks. A directory inside a crate cannot escape its scan.
fn source_scan_skips(meta: &Value) -> Vec<PathBuf> {
    let empty = Vec::new();
    let workspace = members(meta);
    // Directories Cargo treats as other packages: each member's own directory,
    // and each path the workspace's manifest excludes.
    let mut skip: Vec<PathBuf> = meta["packages"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|p| p["id"].as_str().is_some_and(|id| workspace.contains(id)))
        .filter_map(|p| p["manifest_path"].as_str())
        .filter_map(|m| {
            Path::new(m)
                .parent()
                .and_then(|d| std::fs::canonicalize(d).ok())
        })
        .collect();
    // Cargo's output directory, by where Cargo says it is, never a directory
    // that merely has its name: a source module may be called `target` (found in
    // review).
    let member_dirs = skip.clone();
    let mut outside: Vec<PathBuf> = Vec::new();
    if let Some(out) = meta["target_directory"]
        .as_str()
        .and_then(|t| std::fs::canonicalize(t).ok())
    {
        outside.push(out);
    }
    if let Some(root) = meta["workspace_root"].as_str() {
        let excluded = read_toml(&Path::new(root).join("Cargo.toml"))
            .ok()
            .and_then(|t| t.get("workspace")?.get("exclude")?.as_array().cloned())
            .unwrap_or_default();
        outside.extend(
            excluded
                .iter()
                .filter_map(toml::Value::as_str)
                .filter_map(|e| std::fs::canonicalize(Path::new(root).join(e)).ok()),
        );
    }
    // The output directory and excluded paths are skipped only when they lie
    // outside every crate: inside one, `mod` can still load them, so they are
    // scanned like any other source (found in review).
    skip.extend(
        outside
            .into_iter()
            .filter(|o| !member_dirs.iter().any(|m| o.starts_with(m))),
    );
    skip
}

/// Every way unsafe code could get into the workspace, sorted: the workspace not
/// forbidding it, a member not taking the workspace's lints, or a crate root not
/// forbidding it itself.
pub fn no_unsafe(meta: &Value) -> Vec<String> {
    let empty = Vec::new();
    let workspace = members(meta);
    let mut problems = Vec::new();
    if workspace.is_empty() {
        problems.push("the workspace has no members".to_string());
    }
    match meta["workspace_root"].as_str() {
        Some(root) => {
            let manifest = Path::new(root).join("Cargo.toml");
            match read_toml(&manifest) {
                Ok(t) if workspace_forbids_unsafe(&t) => {}
                Ok(_) => problems.push(
                    "the workspace does not set [workspace.lints.rust] unsafe_code = \"forbid\""
                        .to_string(),
                ),
                Err(e) => problems.push(e),
            }
        }
        None => problems.push("cargo metadata names no workspace root".to_string()),
    }
    let skip = source_scan_skips(meta);
    for pkg in meta["packages"].as_array().unwrap_or(&empty) {
        if !pkg["id"].as_str().is_some_and(|id| workspace.contains(id)) {
            continue;
        }
        let pkg_name = pkg["name"].as_str().unwrap_or("?");
        // Edition 2024 makes an `extern` block without `unsafe` a hard error, so with
        // unsafe code forbidden the compiler refuses every foreign block, all
        // assembly and `no_mangle` in a workspace crate. Edition 2021 accepts
        // `extern "C" {}` without `unsafe` even under forbid (found in review,
        // and checked against rustc 1.99.1).
        for target in pkg["targets"].as_array().unwrap_or(&empty) {
            let edition = target["edition"].as_str().unwrap_or("?");
            if edition != "2024" {
                let name = target["name"].as_str().unwrap_or("?");
                problems.push(format!(
                    "{pkg_name}: target {name} is edition {edition}, not 2024"
                ));
            }
        }
        let binding = pkg_name == UNSAFE_BINDING;
        match pkg["manifest_path"]
            .as_str()
            .map(|m| read_toml(Path::new(m)))
        {
            Some(Ok(t)) if !binding && takes_workspace_lints(&t) => {}
            Some(Ok(t)) if binding && has_binding_lints(&t) => {}
            Some(Ok(_)) if binding => problems.push(format!(
                "{pkg_name} does not carry exactly the binding's lints"
            )),
            Some(Ok(_)) => problems.push(format!("{pkg_name} does not take the workspace's lints")),
            Some(Err(e)) => problems.push(e),
            None => problems.push(format!("{pkg_name} has no manifest path")),
        }
        // Every source file of the crate, whatever cfg or feature would compile it:
        // code that no CI build compiles (`#[cfg(not(debug_assertions))]`) is still
        // code a release build of a consumer compiles, with this crate's lints
        // capped (found in review).
        if let Some(dir) = pkg["manifest_path"]
            .as_str()
            .and_then(|m| Path::new(m).parent())
            && !binding
        {
            problems.extend(unsafe_tokens_in(dir, &skip));
        }
        for target in pkg["targets"].as_array().unwrap_or(&empty) {
            let Some(src) = target["src_path"].as_str() else {
                continue;
            };
            // A procedural macro generates code from strings no scan reads, so no
            // workspace crate may be one (found in review).
            if target["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|k| k == "proc-macro"))
            {
                problems.push(format!("{pkg_name} is a procedural macro crate"));
            }
            // The library may not switch itself off with a crate-level `#![cfg]`:
            // that would also switch off the canary's probe (found in review).
            if PROTECTED.contains(&pkg_name)
                && std::fs::read_to_string(src).is_ok_and(|s| has_crate_cfg(&s))
            {
                problems.push(format!("{src} has a crate-level #![cfg]"));
            }
            // A crate root of another extension would escape the token scan.
            if !src.ends_with(".rs") {
                problems.push(format!("{src} is a crate root that is not a .rs file"));
            }
            // And one outside its crate's directory too, for every workspace crate,
            // not only the library's tree (found in review).
            if let Some(dir) = pkg["manifest_path"]
                .as_str()
                .and_then(|m| Path::new(m).parent())
                && !within(Path::new(src), dir)
            {
                problems.push(format!("{src} is a crate root outside its crate"));
            }
            match std::fs::read_to_string(src) {
                Ok(_) if binding => {}
                Ok(text) if forbids_unsafe(&text) => {}
                Ok(_) => problems.push(format!("{src} does not say #![forbid(unsafe_code)]")),
                Err(e) => problems.push(format!("cannot read {src}: {e}")),
            }
        }
    }
    problems.sort();
    problems
}

/// Every `.rs` file under a crate's directory that holds the token `unsafe` or a
/// code `include!`, read as Rust tokens: strings and comments never count, and
/// cfg, features and macro bodies make no difference. A subdirectory holding its
/// own `Cargo.toml` is another package and is left to its own check (the planted
/// fixtures are such a package). A file that does not tokenize is a finding.
pub fn unsafe_tokens_in(dir: &Path, skip: &[PathBuf]) -> Vec<String> {
    source_tokens_in(dir, skip, unsafe_tokens)
}

/// Networking in every workspace crate in the library's normal dependency
/// graph, sorted; empty passes. Metadata enables every feature, and policy runs
/// this for every shipping target. Walk through outside crates too, but scan only
/// workspace sources: outside crates are reviewed through cargo-vet. The CLI's
/// own dependencies are outside this rule. Scan tests and cfg-disabled modules
/// too, using the unsafe check's walker.
pub fn no_network(meta: &Value) -> Vec<String> {
    let workspace = members(meta);
    let skip = source_scan_skips(meta);
    let mut found = Vec::new();
    let packages: HashMap<&str, &Value> = meta["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes: HashMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let mut queue = VecDeque::new();
    for want in PROTECTED {
        let roots: Vec<_> = packages
            .iter()
            .filter(|(id, p)| workspace.contains(*id) && p["name"] == *want)
            .map(|(id, _)| *id)
            .collect();
        if roots.is_empty() {
            found.push(format!("protected crate {want} is not a workspace member"));
        }
        queue.extend(roots);
    }
    let mut seen = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        match nodes.get(id) {
            Some(node) => {
                for dep in node["deps"].as_array().into_iter().flatten() {
                    // A normal edge can share a package with a build/dev edge.
                    if dep["dep_kinds"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|kind| kind["kind"].is_null())
                        && let Some(dep_id) = dep["pkg"].as_str()
                    {
                        queue.push_back(dep_id);
                    }
                }
            }
            None => found.push(format!("{id} has no dependency node")),
        }
    }
    for pkg in meta["packages"].as_array().into_iter().flatten() {
        let name = pkg["name"].as_str().unwrap_or("?");
        if !pkg["id"]
            .as_str()
            .is_some_and(|id| workspace.contains(id) && seen.contains(id))
        {
            continue;
        }
        if name == UNSAFE_BINDING {
            // Cargo can rename the provider before Rust's imports are scanned.
            // Keep every raw provider reference under one of the checked names.
            for dep in pkg["dependencies"].as_array().into_iter().flatten() {
                if dep["name"] == "aws-lc-sys"
                    && let Some(alias) = dep["rename"].as_str()
                    && !["aws_lc_sys", "sys"].contains(&alias.replace('-', "_").as_str())
                {
                    found.push(format!(
                        "{name} renames aws-lc-sys to {alias}: only aws_lc_sys or sys are checked"
                    ));
                }
            }
        }
        match pkg["manifest_path"]
            .as_str()
            .and_then(|m| Path::new(m).parent())
        {
            Some(dir) => {
                found.extend(source_tokens_in(dir, &skip, network_tokens));
                let allowed = format!(
                    "{} uses Secret Service transport API",
                    // One component at a time, so the path prints as the scan reports it on Windows.
                    dir.join("src")
                        .join("store")
                        .join("keys")
                        .join("os.rs")
                        .display()
                );
                found.extend(
                    source_tokens_in(dir, &skip, secret_service_tokens)
                        .into_iter()
                        .filter(|finding| !(name == "qso-graph-trust" && *finding == allowed)),
                );
                if name == UNSAFE_BINDING {
                    found.extend(source_tokens_in(dir, &skip, binding_tokens));
                }
            }
            None => found.push(format!("{name} has no manifest directory")),
        }
    }
    found.sort();
    found
}

/// Only the credential backend may use Secret Service, and only its connection, encryption-mode
/// and error types. Public session encrypt/decrypt functions, globs and namespace aliases cannot
/// turn the transport exception into a signing/certificate primitive. Scan cfg-disabled code too.
pub fn secret_service_tokens(tokens: proc_macro2::TokenStream) -> Vec<&'static str> {
    use proc_macro2::TokenTree;
    fn approved(tree: &syn::UseTree, prefix: &str) -> bool {
        match tree {
            syn::UseTree::Path(p) => approved(
                &p.tree,
                &format!("{prefix}{}::", p.ident.to_string().trim_start_matches("r#")),
            ),
            syn::UseTree::Group(g) => g.items.iter().all(|t| approved(t, prefix)),
            syn::UseTree::Name(n) => ["Error", "EncryptionType", "blocking::SecretService"]
                .contains(
                    &format!("{prefix}{}", n.ident.to_string().trim_start_matches("r#")).as_str(),
                ),
            syn::UseTree::Rename(n) => ["Error", "EncryptionType", "blocking::SecretService"]
                .contains(
                    &format!("{prefix}{}", n.ident.to_string().trim_start_matches("r#")).as_str(),
                ),
            _ => false,
        }
    }
    let trees: Vec<_> = tokens.into_iter().collect();
    let ident = |i: usize, name: &str| matches!(trees.get(i), Some(TokenTree::Ident(id)) if id.to_string().trim_start_matches("r#") == name);
    let colon = |i: usize| matches!(trees.get(i), Some(TokenTree::Punct(p)) if p.as_char() == ':');
    let mut found = Vec::new();
    for (i, tree) in trees.iter().enumerate() {
        if ident(i, "secret_service") {
            found.push("uses Secret Service transport API");
            let permitted = colon(i + 1)
                && colon(i + 2)
                && match trees.get(i + 3) {
                    Some(TokenTree::Group(g)) => {
                        syn::parse2::<syn::UseTree>(TokenTree::Group(g.clone()).into())
                            .is_ok_and(|t| approved(&t, ""))
                    }
                    Some(TokenTree::Ident(_)) => {
                        ident(i + 3, "Error")
                            || ident(i + 3, "EncryptionType")
                            || (ident(i + 3, "blocking")
                                && colon(i + 4)
                                && colon(i + 5)
                                && ident(i + 6, "SecretService"))
                    }
                    _ => false,
                };
            if !permitted {
                found.push("uses Secret Service outside the permitted transport API");
            }
        }
        if let TokenTree::Group(g) = tree {
            found.extend(secret_service_tokens(g.stream()));
        }
    }
    found
}

/// The binding can use unsafe blocks, but cannot load unscanned code or define
/// macros. Raw AWS-LC items must be named explicitly, either through
/// `aws_lc_sys` or its sole namespace alias `use aws_lc_sys as sys;`. Individual
/// allowed items may be renamed; namespace re-exports and glob imports cannot
/// hide which provider API is used. All groups are scanned, whatever their cfg.
pub fn binding_tokens(tokens: proc_macro2::TokenStream) -> Vec<&'static str> {
    use proc_macro2::TokenTree;

    fn ident(tree: Option<&TokenTree>, want: &str) -> bool {
        matches!(tree, Some(TokenTree::Ident(id))
            if id.to_string().trim_start_matches("r#") == want)
    }

    fn allowed(name: &proc_macro2::Ident) -> bool {
        BINDING_AWS_LC_ALLOWED.contains(&name.to_string().trim_start_matches("r#"))
    }

    fn imports(tree: &syn::UseTree) -> bool {
        match tree {
            syn::UseTree::Name(n) => allowed(&n.ident),
            syn::UseTree::Rename(n) => allowed(&n.ident),
            syn::UseTree::Group(g) => g.items.iter().all(imports),
            // No submodules or globs in the provider's allowed surface.
            _ => false,
        }
    }

    fn scan(tokens: proc_macro2::TokenStream) -> Vec<&'static str> {
        let trees: Vec<_> = tokens.into_iter().collect();
        let mut found = Vec::new();
        let colon =
            |i: usize| matches!(trees.get(i), Some(TokenTree::Punct(p)) if p.as_char() == ':');
        for (i, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Ident(_) => {
                    if ident(Some(tree), "include_str") || ident(Some(tree), "include_bytes") {
                        found.push(
                            "loads a file through include_str or include_bytes in the binding",
                        );
                    }
                    if !ident(Some(tree), "aws_lc_sys") && !ident(Some(tree), "sys") {
                        continue;
                    }
                    // The one namespace import, with raw spellings accepted.
                    let namespace_import = |start: usize| {
                        ident(trees.get(start), "use")
                            && ident(trees.get(start + 1), "aws_lc_sys")
                            && ident(trees.get(start + 2), "as")
                            && ident(trees.get(start + 3), "sys")
                            && matches!(trees.get(start + 4), Some(TokenTree::Punct(p)) if p.as_char() == ';')
                    };
                    if (i >= 1 && namespace_import(i - 1)) || (i >= 3 && namespace_import(i - 3)) {
                        continue;
                    }
                    let permitted = colon(i + 1)
                        && colon(i + 2)
                        && match trees.get(i + 3) {
                            Some(TokenTree::Ident(item)) => allowed(item),
                            Some(TokenTree::Group(g)) => {
                                syn::parse2::<syn::UseTree>(TokenTree::Group(g.clone()).into())
                                    .is_ok_and(|tree| imports(&tree))
                            }
                            _ => false,
                        };
                    if !permitted {
                        found.push("uses AWS-LC outside BINDING_AWS_LC_ALLOWED (no namespace aliases or glob imports)");
                    }
                }
                TokenTree::Group(g) => found.extend(scan(g.stream())),
                _ => {}
            }
        }
        found
    }

    let mut found: Vec<_> = unsafe_tokens(tokens.clone())
        .into_iter()
        .filter(|what| *what != "uses unsafe")
        .collect();
    found.extend(scan(tokens));
    found
}

fn source_tokens_in(
    dir: &Path,
    skip: &[PathBuf],
    scan: fn(proc_macro2::TokenStream) -> Vec<&'static str>,
) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            found.push(format!("{} cannot be read", d.display()));
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                found.push(format!("{} has an entry that cannot be read", d.display()));
                continue;
            };
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                found.push(format!("{} cannot be read", path.display()));
                continue;
            };
            // No symbolic links in a workspace crate, as in the library's tree: one
            // can point anywhere, and the canary's copy cannot follow it either
            // (found in review).
            if kind.is_symlink() {
                found.push(format!("{} is a symbolic link", path.display()));
                continue;
            }
            if kind.is_dir() {
                // Left out only when Cargo itself treats it as something else:
                // another package of the workspace, or a path its manifest
                // excludes (the planted fixtures). A Cargo.toml alone is not
                // enough (found in review: a decoy one hid a directory).
                let canon = std::fs::canonicalize(&path).ok();
                let other = canon.as_ref().is_some_and(|c| skip.iter().any(|s| s == c));
                if !other {
                    stack.push(path);
                }
            } else if !path.extension().is_some_and(|e| e == "rs") {
                // Only Rust, manifests and notes in a crate: a file of any other
                // kind could be compiled as code through a path this scan cannot
                // follow, so it is not allowed there (found in review).
                if !path.extension().is_some_and(|e| e == "toml" || e == "md") {
                    found.push(format!(
                        "{} is not a .rs, .toml or .md file",
                        path.display()
                    ));
                }
            } else {
                // A file that cannot be read is a finding, never empty text that
                // scans clean (found in review).
                let text = match std::fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(e) => {
                        found.push(format!(
                            "{} cannot be read as UTF-8 text: {e}",
                            path.display()
                        ));
                        continue;
                    }
                };
                // No shebangs in a workspace crate: Rust decides one with rules about
                // whitespace and comments that were misread twice (found in
                // review), and the crates need none. A file beginning `#!` must
                // begin `#![`.
                let body = text.strip_prefix('\u{feff}').unwrap_or(&text);
                if body.starts_with("#!") && !body.starts_with("#![") {
                    found.push(format!(
                        "{} begins with #! but not #![: no shebangs in a workspace crate",
                        path.display()
                    ));
                    continue;
                }
                match body.parse::<proc_macro2::TokenStream>() {
                    Ok(tokens) => {
                        for what in scan(tokens) {
                            found.push(format!("{} {what}", path.display()));
                        }
                    }
                    Err(e) => {
                        found.push(format!("{} does not tokenize as Rust: {e}", path.display()))
                    }
                }
            }
        }
    }
    found.sort();
    found
}

/// Network type identifiers and the `net` path segment, including raw spellings,
/// grouped and aliased imports. Comments and literals are not identifiers; cfg
/// does not hide tokens. A plain local variable called `net` is not a path.
pub fn network_tokens(tokens: proc_macro2::TokenStream) -> Vec<&'static str> {
    fn scan(tokens: proc_macro2::TokenStream, mut in_use: bool) -> Vec<&'static str> {
        use proc_macro2::TokenTree;
        const TYPES: &[(&str, &str)] = &[
            ("TcpStream", "uses network identifier TcpStream"),
            ("TcpListener", "uses network identifier TcpListener"),
            ("UdpSocket", "uses network identifier UdpSocket"),
            ("UnixStream", "uses network identifier UnixStream"),
            ("UnixListener", "uses network identifier UnixListener"),
            ("UnixDatagram", "uses network identifier UnixDatagram"),
            ("ToSocketAddrs", "uses network identifier ToSocketAddrs"),
            ("SocketAddr", "uses network identifier SocketAddr"),
            ("SocketAddrV4", "uses network identifier SocketAddrV4"),
            ("SocketAddrV6", "uses network identifier SocketAddrV6"),
            ("IpAddr", "uses network identifier IpAddr"),
        ];
        let trees: Vec<_> = tokens.into_iter().collect();
        let colon =
            |i: usize| matches!(trees.get(i), Some(TokenTree::Punct(p)) if p.as_char() == ':');
        let mut found = Vec::new();
        for (i, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Ident(id) => {
                    let name = id.to_string();
                    let name = name.strip_prefix("r#").unwrap_or(&name);
                    if name == "use" {
                        in_use = true;
                    }
                    let alias =
                        i > 0 && matches!(&trees[i - 1], TokenTree::Ident(id) if id == "as");
                    if name == "net"
                        && ((in_use && !alias)
                            || (i >= 2 && colon(i - 2) && colon(i - 1))
                            || (colon(i + 1) && colon(i + 2)))
                    {
                        found.push("uses network path segment net");
                    }
                    if let Some((_, what)) = TYPES.iter().find(|(n, _)| *n == name) {
                        found.push(*what);
                    }
                }
                TokenTree::Group(g) => found.extend(scan(g.stream(), in_use)),
                TokenTree::Punct(p) if p.as_char() == ';' => in_use = false,
                _ => {}
            }
        }
        found
    }
    scan(tokens, false)
}

/// Identifiers no workspace source may contain, wherever they appear, with what
/// each brings: matched as identifiers, never text, after removing `r#`, so a
/// raw identifier, an import alias (`use core::include as load` names
/// `include`) and any macro delimiter are all caught (found in review).
const REFUSED_IDENTS: &[(&str, &str)] = &[
    ("unsafe", "uses unsafe"),
    // A macro can assemble code no scan sees whole (review found five ways
    // in turn), so the workspace's crates define none.
    ("macro_rules", "defines a macro"),
    // `macro`, the unstable declarative macro (found in review).
    ("macro", "defines a macro"),
    ("include", "uses include"),
    ("asm", "uses asm"),
    ("global_asm", "uses global_asm"),
    ("naked_asm", "uses naked_asm"),
];

/// What in a token stream could bring unsafe code: the keyword `unsafe` anywhere
/// (blocks, functions, traits, impls, extern blocks, `#[unsafe(...)]`), and
/// `include!`, which compiles another file's code in place; and `#[path]`, which
/// makes a module of any file.
pub fn unsafe_tokens(tokens: proc_macro2::TokenStream) -> Vec<&'static str> {
    use proc_macro2::TokenTree;
    const DANGLING: &str = "has a # that does not begin an attribute";
    let mut found = Vec::new();
    // Whether the last token was `#` (an outer attribute) or `#` then `!` (inner).
    let mut after_hash = false;
    let mut last_hash = false;
    for tree in tokens {
        // In Rust a `#` only ever begins an attribute, `#[...]` or `#![...]`. One
        // followed by anything else is a piece a macro could join to brackets
        // passed separately, assembling `#[path]` where no scan sees it (found by
        // Found in review: `# $a` with `$a` = `[path = "..."]`).
        let pending = after_hash || last_hash;
        let mut hash_now = false;
        match &tree {
            TokenTree::Ident(i) => {
                if pending {
                    found.push(DANGLING);
                }
                // Raw identifiers name the same thing: `r#include` is `include`.
                let name = i.to_string();
                let name = name.strip_prefix("r#").unwrap_or(&name);
                if let Some((_, what)) = REFUSED_IDENTS.iter().find(|(n, _)| *n == name) {
                    found.push(*what);
                }
                after_hash = false;
                last_hash = false;
                continue;
            }
            TokenTree::Punct(p) if p.as_char() == '!' && last_hash => {
                // `#!`: the attribute's brackets come next.
                after_hash = true;
                last_hash = false;
                continue;
            }
            TokenTree::Punct(p) => {
                if pending {
                    found.push(DANGLING);
                }
                hash_now = p.as_char() == '#';
            }
            TokenTree::Group(g) => {
                let attribute = pending && g.delimiter() == proc_macro2::Delimiter::Bracket;
                if pending && !attribute {
                    found.push(DANGLING);
                }
                // `path = ...` loads a module from any file, `.rs` or not, which
                // this scan would not read (found in review); the workspace's
                // crates do not need it, so it is refused. Only in an attribute:
                // with no macros allowed and no lone `#`, every attribute in the
                // source is a literal `#[...]`, and a `path = 1` binding inside an
                // array is not one (found in review).
                let bracket = g.delimiter() == proc_macro2::Delimiter::Bracket;
                if attribute && assigns_path(g.stream()) {
                    found.push("uses #[path]");
                }
                // Unstable features: stable code needs none, and they include
                // ways to build unsafe code from pieces (found in review).
                // Anywhere in the attribute, so inside cfg_attr too (found in
                // review); `cfg(feature = "x")` selects a Cargo feature and is not one.
                if attribute && enables_feature(g.stream()) {
                    found.push("enables an unstable feature");
                }
                // A name a macro substitutes: `#[$name = ...]`, `[$name = ...]` or
                // `cfg_attr(..., $name = ...)` could be made `path` by the caller.
                if bracket && (attribute && has_dollar(g.stream()) || names_by_variable(g.stream()))
                {
                    found.push("builds an attribute from a macro variable");
                }
                // A derive macro may parse a string in its attribute as Rust:
                // `#[serde(bound = "... unsafe { ... } ...")]` (found in
                // review). Every string in an attribute but a doc comment is read
                // as tokens and held to the same rules.
                // Strings in an attribute a derive macro may parse as Rust, read as
                // tokens; Rust's own prose attributes excepted, inside `cfg_attr` too
                // (found in review, rounds 31 to 33).
                if attribute {
                    for text in code_strings(g.stream()) {
                        if let Ok(inner) = text.parse::<proc_macro2::TokenStream>() {
                            found.extend(unsafe_tokens(inner));
                        }
                    }
                }
                found.extend(unsafe_tokens(g.stream()));
            }
            TokenTree::Literal(_) => {
                if pending {
                    found.push(DANGLING);
                }
            }
        }
        after_hash = false;
        last_hash = hash_now;
    }
    if after_hash || last_hash {
        found.push(DANGLING);
    }
    found
}

/// Whether a bracket group opens `$name =`, or holds a `cfg_attr(...)` with a `$`
/// in it: the shapes in which a macro variable names an attribute.
fn names_by_variable(tokens: proc_macro2::TokenStream) -> bool {
    use proc_macro2::TokenTree;
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let opens_assignment = matches!(
        trees.as_slice(),
        [TokenTree::Punct(d), TokenTree::Ident(_), TokenTree::Punct(e), ..]
            if d.as_char() == '$' && e.as_char() == '='
    );
    let cfg_attr = trees.windows(2).any(|w| {
        matches!(&w[0], TokenTree::Ident(i) if i == "cfg_attr")
            && matches!(&w[1], TokenTree::Group(g) if has_dollar(g.stream()))
    });
    opens_assignment || cfg_attr
}

/// Whether an attribute's tokens hold `feature(...)` at any depth, raw `r#feature`
/// included.
fn enables_feature(tokens: proc_macro2::TokenStream) -> bool {
    use proc_macro2::TokenTree;
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    trees.iter().enumerate().any(|(i, tree)| match tree {
        TokenTree::Ident(id) => {
            let name = id.to_string();
            name.strip_prefix("r#").unwrap_or(&name) == "feature"
                && matches!(trees.get(i + 1), Some(TokenTree::Group(g))
                    if g.delimiter() == proc_macro2::Delimiter::Parenthesis)
        }
        TokenTree::Group(g) => enables_feature(g.stream()),
        _ => false,
    })
}

/// Built-in attributes whose string arguments Rust treats as text, never as code:
/// each one in the Rust Reference's index of built-in attributes that takes a
/// string, which is a reason, a name, a number or a file a debugger reads.
/// Built-in attribute names cannot be taken by a macro, so none is a macro's
/// input. Not here: `link_name`, which the native check refuses, and
/// `export_name` and `link_section`, which are unsafe attributes the lints refuse.
const PROSE_ATTRIBUTES: &[&str] = &[
    "allow",
    "cfg",
    "crate_name",
    "crate_type",
    "debugger_visualizer",
    "deny",
    "deprecated",
    "diagnostic",
    "doc",
    "expect",
    "forbid",
    "ignore",
    "must_use",
    "recursion_limit",
    "should_panic",
    "target_feature",
    "type_length_limit",
    "warn",
    "windows_subsystem",
];

/// The strings in one attribute's tokens that a macro might read as code: none
/// for Rust's own prose attributes; for `cfg_attr(predicate, a, b, ...)`, those of
/// each wrapped attribute in turn; otherwise every string in it.
fn code_strings(attr: proc_macro2::TokenStream) -> Vec<String> {
    use proc_macro2::TokenTree;
    let trees: Vec<TokenTree> = attr.into_iter().collect();
    // `r#must_use` is `must_use` (found in review).
    let first = match trees.first() {
        Some(TokenTree::Ident(i)) => {
            let name = i.to_string();
            name.strip_prefix("r#").unwrap_or(&name).to_string()
        }
        _ => String::new(),
    };
    if PROSE_ATTRIBUTES.contains(&first.as_str()) {
        return Vec::new();
    }
    if first == "cfg_attr" {
        let Some(TokenTree::Group(args)) = trees.get(1) else {
            return strings_in(trees.into_iter().collect());
        };
        // Split the arguments at top-level commas; the first is the predicate,
        // whose strings (`feature = "x"`) are cfg values, not code.
        let mut parts: Vec<Vec<TokenTree>> = vec![Vec::new()];
        for tree in args.stream() {
            if matches!(&tree, TokenTree::Punct(p) if p.as_char() == ',') {
                parts.push(Vec::new());
            } else if let Some(last) = parts.last_mut() {
                last.push(tree);
            }
        }
        return parts
            .into_iter()
            .skip(1)
            .flat_map(|part| code_strings(part.into_iter().collect()))
            .collect();
    }
    strings_in(trees.into_iter().collect())
}

/// Every string literal's contents in a token stream, at any depth, read through
/// syn so escapes and raw strings decode as Rust decodes them.
fn strings_in(tokens: proc_macro2::TokenStream) -> Vec<String> {
    use proc_macro2::TokenTree;
    let mut found = Vec::new();
    for tree in tokens {
        match tree {
            TokenTree::Literal(l) => {
                if let Ok(s) = syn::parse_str::<syn::LitStr>(&l.to_string()) {
                    found.push(s.value());
                }
            }
            TokenTree::Group(g) => found.extend(strings_in(g.stream())),
            _ => {}
        }
    }
    found
}

/// Whether a token stream holds a `$` at any depth.
fn has_dollar(tokens: proc_macro2::TokenStream) -> bool {
    use proc_macro2::TokenTree;
    tokens.into_iter().any(|tree| match tree {
        TokenTree::Punct(p) => p.as_char() == '$',
        TokenTree::Group(g) => has_dollar(g.stream()),
        _ => false,
    })
}

/// Whether a token stream holds `path =` at any depth.
fn assigns_path(tokens: proc_macro2::TokenStream) -> bool {
    use proc_macro2::TokenTree;
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    trees.iter().enumerate().any(|(i, tree)| match tree {
        TokenTree::Ident(id) => {
            let name = id.to_string();
            // A standalone `=`: in `path == 0` or `path => x` the `=` is joined to
            // the next character, which is an expression, not an attribute (found
            // in review).
            name.strip_prefix("r#").unwrap_or(&name) == "path"
                && matches!(trees.get(i + 1), Some(TokenTree::Punct(p))
                    if p.as_char() == '=' && p.spacing() == proc_macro2::Spacing::Alone)
        }
        TokenTree::Group(g) => assigns_path(g.stream()),
        _ => false,
    })
}

fn read_toml(path: &Path) -> Result<toml::Table, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    text.parse::<toml::Table>()
        .map_err(|e| format!("{} is not valid TOML: {e}", path.display()))
}

/// Whether a member's manifest says `[lints] workspace = true` and nothing else
/// under `[lints]`, read as TOML, so text inside a string never counts (found in
/// review).
pub fn takes_workspace_lints(manifest: &toml::Table) -> bool {
    manifest
        .get("lints")
        .and_then(toml::Value::as_table)
        .is_some_and(|l| l.len() == 1 && l.get("workspace") == Some(&toml::Value::Boolean(true)))
}

/// Whether a manifest's `[lints]` is exactly [`BINDING_LINTS`], read as TOML.
pub fn has_binding_lints(manifest: &toml::Table) -> bool {
    let want: toml::Table = toml::from_str(BINDING_LINTS).unwrap_or_default();
    manifest.get("lints").and_then(toml::Value::as_table) == Some(&want)
}

/// Whether the workspace's manifest sets `unsafe_code = "forbid"` for every member.
pub fn workspace_forbids_unsafe(manifest: &toml::Table) -> bool {
    let rust = manifest
        .get("workspace")
        .and_then(|w| w.get("lints"))
        .and_then(|l| l.get("rust"))
        .and_then(|r| r.get("unsafe_code"));
    match rust {
        Some(toml::Value::String(s)) => s == "forbid",
        Some(toml::Value::Table(t)) => {
            t.get("level") == Some(&toml::Value::String("forbid".into()))
        }
        _ => false,
    }
}

/// The one RUSTFLAGS line a workflow may hold besides `RUSTFLAGS: -D warnings`: binaries.yml's,
/// which links Windows' C runtime into `qg-trust.exe`, so it needs no Visual C++ runtime installed.
pub const WINDOWS_CRT_STATIC: &str =
    r#"if [ "$RUNNER_OS" = Windows ]; then export RUSTFLAGS="-C target-feature=+crt-static"; fi"#;

/// Every way a build of this repository could have its lints weakened, sorted.
/// `--cap-lints` overrides even `forbid(unsafe_code)` (found in review, and
/// checked against rustc 1.99.1), as do `-A`/`-W`/`--force-warn unsafe_code`. So:
/// the repository's one Cargo configuration file is `.cargo/config.toml`, holding
/// only `[alias]`; no other Cargo configuration file exists anywhere in it; no
/// workflow mentions a lint cap or the lint itself; and the environment the check
/// runs in (CI's, in CI) passes no such flag.
pub fn no_lint_overrides(root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let config = root.join(".cargo").join("config.toml");
    match read_toml(&config) {
        Ok(t) => {
            for key in t.keys().filter(|k| k.as_str() != "alias") {
                problems.push(format!(
                    ".cargo/config.toml has [{key}]: only [alias] is allowed"
                ));
            }
            // An alias can pass any flag (found in review), so the one alias is
            // exactly the one this repository needs.
            let want: toml::Table =
                [("xtask".to_string(), toml::Value::String(XTASK_ALIAS.into()))]
                    .into_iter()
                    .collect();
            if let Some(alias) = t.get("alias")
                && alias.as_table() != Some(&want)
            {
                problems.push(format!(
                    ".cargo/config.toml's [alias] must be exactly xtask = \"{XTASK_ALIAS}\""
                ));
            }
        }
        Err(e) => problems.push(e),
    }
    // The pinned stable toolchain, which refuses `cargo-features`, so manifest
    // profile flags and other unstable Cargo features cannot be switched on;
    // and no `rustflags` in any profile (found in review).
    match read_toml(&root.join("rust-toolchain.toml")) {
        Ok(t) => {
            let channel = t
                .get("toolchain")
                .and_then(|c| c.get("channel"))
                .and_then(toml::Value::as_str);
            if !channel.is_some_and(is_stable_version) {
                problems.push(format!(
                    "rust-toolchain.toml must name an exact stable release, not {channel:?}"
                ));
            }
        }
        Err(e) => problems.push(e),
    }
    match read_toml(&root.join("Cargo.toml")) {
        Ok(t) => {
            if t.contains_key("cargo-features") {
                problems.push("Cargo.toml has cargo-features".to_string());
            }
            // A patch or replacement holds only here: a consumer building QGT as a
            // dependency ignores it and gets the crate the patch stood in for,
            // unchecked (found in review). What is checked must be what
            // consumers build, so neither is allowed.
            for key in ["patch", "replace"] {
                if t.contains_key(key) {
                    problems.push(format!("Cargo.toml has [{key}]"));
                }
            }
            if let Some(profiles) = t.get("profile") {
                for path in rustflags_in(profiles, "profile") {
                    problems.push(format!("Cargo.toml sets {path}"));
                }
            }
        }
        Err(e) => problems.push(e),
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            problems.push(format!("{} cannot be read", d.display()));
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                problems.push(format!("{} has an entry that cannot be read", d.display()));
                continue;
            };
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if is_dir {
                if !(d == root && matches!(name.as_str(), "target" | ".git")) {
                    stack.push(path);
                }
                continue;
            }
            // rustup reads `rust-toolchain` before `rust-toolchain.toml`, and the
            // nearest one to where Cargo runs, so the root's `.toml` is the only
            // toolchain file there may be (found in review).
            // Names compared without regard to case, on every host: on Windows and
            // macOS `.CARGO/config.toml` is a Cargo configuration file (found in
            // review). Only the root's exact `rust-toolchain.toml` and
            // `.cargo/config.toml` are allowed.
            let lower = name.to_ascii_lowercase();
            let exact_root_toolchain = d == root && name == "rust-toolchain.toml";
            if lower == "rust-toolchain"
                || (lower == "rust-toolchain.toml" && !exact_root_toolchain)
            {
                problems.push(format!("{} is a toolchain file", path.display()));
            }
            let in_cargo_dir = d
                .file_name()
                .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(".cargo"));
            if in_cargo_dir && matches!(lower.as_str(), "config" | "config.toml") && path != config
            {
                problems.push(format!("{} is a Cargo configuration file", path.display()));
            }
            let in_workflows = d.ends_with(Path::new(".github").join("workflows"));
            if in_workflows {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                for word in WORKFLOW_REFUSED {
                    if text.contains(word) {
                        problems.push(format!("workflow {name} mentions {word}"));
                    }
                }
                // RUSTFLAGS only as the one workflow-wide line; a job or step setting
                // it would not reach this check's own environment. The one exception is
                // the release's Windows build linking the C runtime in, exactly as
                // WINDOWS_CRT_STATIC says it, in binaries.yml alone: a target feature,
                // which neither weakens a lint nor links anything but Microsoft's runtime.
                for line in text.lines().filter(|l| l.contains("RUSTFLAGS")) {
                    let crt_static = name == "binaries.yml" && line.trim() == WINDOWS_CRT_STATIC;
                    if line.trim() != "RUSTFLAGS: -D warnings" && !crt_static {
                        problems.push(format!("workflow {name} sets RUSTFLAGS: {}", line.trim()));
                    }
                }
            }
        }
    }
    problems.extend(env_problems(std::env::vars()));
    problems.extend(outside_configs(root));
    problems.sort();
    problems
}

/// Every Cargo configuration file Cargo would read from outside the repository,
/// each folder above it and Cargo's home, that changes how the repository
/// compiles: a crate's own configuration stays inside the repository, but a configuration above the
/// checkout reaches every build in it, and the canary, working elsewhere, would
/// not see it (found in review).
pub fn outside_configs(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    let mut dir = std::fs::canonicalize(root)
        .ok()
        .and_then(|r| r.parent().map(Path::to_path_buf));
    while let Some(d) = dir {
        files.push(d.join(".cargo"));
        dir = d.parent().map(Path::to_path_buf);
    }
    // The effective Cargo home: CARGO_HOME if set, otherwise the user's home
    // directory as the platform defines it (USERPROFILE on Windows; found in
    // review). Cargo reads no other home, so neither does this.
    files.extend(
        std::env::var_os("CARGO_HOME")
            // Empty is unset, as Cargo treats it (found in review).
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::home_dir().map(|h| h.join(".cargo"))),
    );
    let mut problems = Vec::new();
    for cargo_dir in files {
        // Each filename probed directly, as Cargo does: a directory that cannot be
        // listed can still have a file Cargo opens (found in review). Only
        // "not found" is no finding; on a case-insensitive file system the probe
        // finds any case of the name, as Cargo's does.
        // Cargo reads `config` when it exists and `config.toml` only otherwise, so
        // the first that exists is the one checked (found in review).
        for name in ["config", "config.toml"] {
            let path = cargo_dir.join(name);
            let read = std::fs::read_to_string(&path);
            let exists = !matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::NotADirectory);
            match read {
                Ok(text) => match text.parse::<toml::Table>() {
                    Ok(t) => {
                        for key in weakening_keys(&t) {
                            problems.push(format!("{} sets {key}", path.display()));
                        }
                    }
                    Err(e) => problems.push(format!("{} is not valid TOML: {e}", path.display())),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {}
                Err(e) => problems.push(format!("{} cannot be read: {e}", path.display())),
            }
            if exists {
                break;
            }
        }
    }
    problems
}

/// The settings in a Cargo configuration that change how code is compiled:
/// flags, the compiler, wrappers, linkers, environment, unstable features and
/// further files.
pub fn weakening_keys(config: &toml::Table) -> Vec<String> {
    let mut found = Vec::new();
    for key in ["env", "unstable", "include", "profile"] {
        if config.contains_key(key) {
            found.push(format!("[{key}]"));
        }
    }
    if let Some(build) = config.get("build").and_then(toml::Value::as_table) {
        for key in [
            "rustflags",
            "rustdocflags",
            "rustc",
            "rustc-wrapper",
            "rustc-workspace-wrapper",
        ] {
            if build.contains_key(key) {
                found.push(format!("build.{key}"));
            }
        }
    }
    if let Some(targets) = config.get("target").and_then(toml::Value::as_table) {
        for (name, target) in targets {
            for key in ["rustflags", "linker", "runner"] {
                if target.get(key).is_some() {
                    found.push(format!("target.{name}.{key}"));
                }
            }
        }
    }
    found
}

/// Whether a toolchain channel is an exact stable release, such as `1.99.1`.
fn is_stable_version(channel: &str) -> bool {
    let parts: Vec<&str> = channel.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Every `rustflags` key anywhere under a TOML value, as a dotted path.
fn rustflags_in(value: &toml::Value, path: &str) -> Vec<String> {
    let mut found = Vec::new();
    if let Some(table) = value.as_table() {
        for (key, inner) in table {
            let here = format!("{path}.{key}");
            if key == "rustflags" {
                found.push(here);
            } else {
                found.extend(rustflags_in(inner, &here));
            }
        }
    }
    found
}

/// Whether the compiler that actually runs from the repository's root is the
/// release `rust-toolchain.toml` pins, and a stable one: whatever file, override
/// or environment selected it, this is the compiler that builds QGT.
pub fn pinned_compiler(root: &Path) -> Vec<String> {
    let pinned = match read_toml(&root.join("rust-toolchain.toml")) {
        Ok(t) => t
            .get("toolchain")
            .and_then(|c| c.get("channel"))
            .and_then(toml::Value::as_str)
            .unwrap_or("")
            .to_string(),
        Err(e) => return vec![e],
    };
    let out = Command::new("rustc").current_dir(root).arg("-vV").output();
    match out {
        Ok(o) if o.status.success() => {
            compiler_problems(&String::from_utf8_lossy(&o.stdout), &pinned)
        }
        Ok(o) => vec![format!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&o.stderr)
        )],
        Err(e) => vec![format!("cannot run rustc: {e}")],
    }
}

/// What is wrong with `rustc -vV`'s report against the pinned release.
pub fn compiler_problems(report: &str, pinned: &str) -> Vec<String> {
    let release = report
        .lines()
        .find_map(|l| l.strip_prefix("release: "))
        .unwrap_or("")
        .trim();
    if release == pinned && is_stable_version(release) {
        Vec::new()
    } else {
        vec![format!(
            "the compiler that runs is {release:?}, not the pinned stable {pinned:?}"
        )]
    }
}

/// The one alias the repository's Cargo configuration may hold.
pub const XTASK_ALIAS: &str = "run --quiet --locked --package xtask --";

/// Words no workflow may contain: each is a way to hand the compiler flags,
/// another configuration, another compiler or a linker argument that this
/// check would not see (found in review). Failing on the word, even in a
/// comment, fails closed.
const WORKFLOW_REFUSED: &[&str] = &[
    "cap-lints",
    "force-warn",
    "unsafe_code",
    "--config",
    "RUSTC",
    "cargo rustc",
    "CARGO_BUILD",
    "CARGO_TARGET",
    "CARGO_ENCODED",
    "link-arg",
];

/// Every variable in an environment that would change how this repository is
/// compiled beyond the allowed lint flags: flags outside [`flags_allowed`], or a
/// different compiler, wrapper or linker (found in review: wrappers and
/// response files reach rustc without passing through RUSTFLAGS's words).
pub fn env_problems(vars: impl IntoIterator<Item = (String, String)>) -> Vec<String> {
    let mut problems = Vec::new();
    for (var, value) in vars {
        // Compared without regard to case: Cargo reads `rustflags` as `RUSTFLAGS`
        // on Windows (found in review).
        let var = var.to_ascii_uppercase();
        // RUSTC_BOOTSTRAP unlocks unstable features on a stable compiler, among
        // them ways to build unsafe code the scan cannot see (found in review).
        if var == "RUSTC_BOOTSTRAP" {
            problems.push(format!("{var} unlocks unstable features: {value}"));
            continue;
        }
        let rustflags = matches!(
            var.as_str(),
            "RUSTFLAGS" | "CARGO_ENCODED_RUSTFLAGS" | "CARGO_BUILD_RUSTFLAGS"
        ) || (var.starts_with("CARGO_TARGET_") && var.ends_with("_RUSTFLAGS"));
        let compiler = matches!(
            var.as_str(),
            "RUSTC" | "RUSTC_WRAPPER" | "RUSTC_WORKSPACE_WRAPPER" | "RUSTC_LINKER"
        ) || (var.starts_with("CARGO_BUILD_")
            && !matches!(var.as_str(), "CARGO_BUILD_JOBS" | "CARGO_BUILD_TARGET_DIR"))
            || (var.starts_with("CARGO_TARGET_") && var != "CARGO_TARGET_DIR");
        if rustflags {
            if !flags_allowed(&value) {
                problems.push(format!("{var} has flags beyond lint levels: {value}"));
            }
        } else if compiler {
            problems.push(format!(
                "{var} changes the compiler, wrapper or linker: {value}"
            ));
        }
    }
    problems.sort();
    problems
}

/// Whether compiler flags are only lint levels (`-D`, `-W`, `-A` and their long
/// forms, each naming a lint), none of them `unsafe_code`. Anything else fails:
/// a lint cap, a response file (`@path`), a native library (`-l`), a codegen or
/// linker option, an unstable flag. An allowlist, because each list of refused
/// flags so far had a way around it (found in review).
pub fn flags_allowed(flags: &str) -> bool {
    let words: Vec<&str> = flags
        .split(|c: char| c.is_whitespace() || c == '\u{1f}')
        .filter(|w| !w.is_empty())
        .collect();
    let lint = |l: &str| {
        !l.is_empty()
            && l != "unsafe_code"
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ':')
    };
    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        if matches!(w, "-D" | "-W" | "-A" | "--deny" | "--warn" | "--allow") {
            if !words.get(i + 1).is_some_and(|l| lint(l)) {
                return false;
            }
            i += 2;
            continue;
        }
        let joined = ["-D", "-W", "-A", "--deny=", "--warn=", "--allow="]
            .iter()
            .find_map(|p| w.strip_prefix(p));
        match joined {
            Some(l) if lint(l) => i += 1,
            _ => return false,
        }
    }
    true
}

/// What the canary appends to the library: unsafe code the compiler must refuse.
/// An anonymous constant holding an empty `unsafe` block: it takes no name and
/// looks none up, so nothing the library declares can collide with it or redirect
/// it (Found in review: a module named `core`, a function of
/// the probe's name, `extern crate self as core`).
pub const CANARY_PROBE: &str =
    "\n// The canary's probe: the compiler must refuse it.\nconst _: () = unsafe {};\n";

/// The canary: build the real library, in a copy of this repository (its
/// manifests and profiles, its Cargo configuration, its toolchain file) with an
/// `unsafe` block added, in this build's real environment (its flags and any
/// wrapper), and require the compiler to refuse it with an `unsafe_code` error.
/// The other checks look for known ways to weaken the lints; this one measures
/// the result on the crate that matters, so a way nobody listed still fails it.
/// It reads the compiler's JSON diagnostics: an `unsafe_code` warning beside an
/// unrelated error is not a refusal (found in review, as were the profile
/// flags a stand-in crate could not see). `extra_env` is for the planted test.
pub fn canary(root: &Path, extra_env: &[(&str, &str)]) -> Result<(), String> {
    let work = fresh_temp_dir("qso-graph-trust-canary")?;
    let result = canary_in(root, &work, extra_env);
    // Only the directory this call created, so cleaning up can never remove
    // anything else (found in review: given a path, it once could).
    let _ = std::fs::remove_dir_all(&work);
    result
}

/// A fresh directory under the system's temporary directory, created by this
/// call (never one that already existed), outside the repository wherever
/// Cargo's output directory is (found in review: inside it, the copy
/// recursed into itself and left a Cargo configuration the policy then found).
pub fn fresh_temp_dir(prefix: &str) -> Result<PathBuf, String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let base = std::path::absolute(std::env::temp_dir())
        .map_err(|e| format!("cannot resolve the temporary directory: {e}"))?;
    for _ in 0..100 {
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = base.join(format!("{prefix}-{}-{n}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot make {}: {e}", dir.display())),
        }
    }
    Err("cannot find a free directory for the canary".into())
}

fn canary_in(root: &Path, work: &Path, extra_env: &[(&str, &str)]) -> Result<(), String> {
    let root_abs = std::fs::canonicalize(root)
        .map_err(|e| format!("cannot resolve {}: {e}", root.display()))?;
    if std::fs::canonicalize(work).is_ok_and(|w| w.starts_with(&root_abs)) {
        return Err(format!(
            "the canary must work outside the repository, not in {} (is TMPDIR inside it?)",
            work.display()
        ));
    }
    let copy = work.join("repo");
    // Cargo's output directory, if it is inside the repository, is left out of the copy.
    let output = std::env::var_os("CARGO_TARGET_DIR").map(|d| root.join(d));
    copy_repository(root, &copy, output.as_deref())?;
    // The library's root as Cargo has it, not an assumed path (found in review).
    let meta = metadata(&copy.join("Cargo.toml"))?;
    let lib = meta["packages"]
        .as_array()
        .and_then(|ps| ps.iter().find(|p| p["name"] == "qso-graph-trust"))
        .and_then(|p| p["targets"].as_array())
        .and_then(|ts| {
            ts.iter().find(|t| {
                t["kind"].as_array().is_some_and(|k| {
                    // Every kind Cargo reports for a library (found in review).
                    k.iter().any(|k| {
                        ["lib", "rlib", "dylib", "cdylib", "staticlib"]
                            .iter()
                            .any(|l| k == l)
                    })
                })
            })
        })
        .and_then(|t| t["src_path"].as_str())
        .map(PathBuf::from)
        .ok_or("the copy has no qso-graph-trust library target")?;
    // Only ever write inside the copy: a library path that resolves elsewhere, such
    // as an absolute path back into the checkout, would put the probe into the
    // real source (found in review).
    let copy_abs = std::fs::canonicalize(&copy)
        .map_err(|e| format!("cannot resolve {}: {e}", copy.display()))?;
    if !std::fs::canonicalize(&lib).is_ok_and(|l| l.starts_with(&copy_abs)) {
        return Err(format!(
            "the library's source {} is not inside the canary's copy: use a relative [lib] path",
            lib.display()
        ));
    }
    let mut source =
        std::fs::read_to_string(&lib).map_err(|e| format!("cannot read {}: {e}", lib.display()))?;
    source.push_str(CANARY_PROBE);
    std::fs::write(&lib, source).map_err(|e| format!("cannot write {}: {e}", lib.display()))?;

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .current_dir(&copy)
        .envs(extra_env.iter().copied())
        .args([
            "check",
            "--quiet",
            "--locked",
            "--all-features",
            "--package",
            "qso-graph-trust",
            "--message-format",
            "json",
            "--target-dir",
        ])
        .arg(work.join("target"))
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .map_err(|e| format!("cannot run cargo for the canary: {e}"))?;
    let refused = refused_by_unsafe_code(&String::from_utf8_lossy(&out.stdout));
    if out.status.success() {
        return Err(
            "the canary compiled: something in this build weakens forbid(unsafe_code)".into(),
        );
    }
    if !refused {
        return Err(format!(
            "the canary failed to build, but not with an unsafe_code error:\n{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Whether Cargo's JSON messages hold an `unsafe_code` diagnostic at level
/// `error`: a warning of it beside some other error is not a refusal (found in
/// review).
pub fn refused_by_unsafe_code(json_lines: &str) -> bool {
    json_lines.lines().any(|line| {
        serde_json::from_str::<Value>(line).is_ok_and(|m| {
            m["reason"] == "compiler-message"
                && m["message"]["level"] == "error"
                && m["message"]["code"]["code"] == "unsafe_code"
        })
    })
}

/// Copy this repository's files to `to`, leaving out `.git`, every `target`
/// directory and Cargo's output directory, so the canary builds what a commit
/// holds. Symbolic links are not followed.
fn copy_repository(from: &Path, to: &Path, output: Option<&Path>) -> Result<(), String> {
    let output = output.and_then(|o| std::fs::canonicalize(o).ok());
    let mut stack = vec![(from.to_path_buf(), to.to_path_buf())];
    while let Some((src, dst)) = stack.pop() {
        std::fs::create_dir_all(&dst).map_err(|e| format!("cannot make {}: {e}", dst.display()))?;
        let entries =
            std::fs::read_dir(&src).map_err(|e| format!("cannot read {}: {e}", src.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read {}: {e}", src.display()))?;
            let path = entry.path();
            let name = entry.file_name();
            let kind = entry
                .file_type()
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            if kind.is_dir() {
                let is_output = output
                    .as_ref()
                    .is_some_and(|o| std::fs::canonicalize(&path).is_ok_and(|p| p == *o));
                // `target` only at the root, where Cargo puts it: a source module
                // may be named `target` (found in review).
                if name == ".git" || (src == from && name == "target") || is_output {
                    continue;
                }
                stack.push((path, dst.join(name)));
            } else if kind.is_file() {
                std::fs::copy(&path, dst.join(&name))
                    .map_err(|e| format!("cannot copy {}: {e}", path.display()))?;
            } else {
                // A link or anything else is not copied silently (found in review).
                return Err(format!(
                    "{} is not a plain file or directory: the canary will not copy it",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Whether a path is the single identifier `name`, raw spelling included:
/// `r#unsafe_code` is `unsafe_code` (found in review).
/// Every program the workspace builds must install [`WIPING_ALLOCATOR`]: every
/// target whose crate types include `bin`, `cdylib` or `staticlib`, examples
/// included, as `cargo install --example` installs one (found in review).
/// Tests, benches and build scripts are not checked: they run on the machine that
/// builds, and none is ever distributed. Its root must hold, at the top level and
/// with no attribute but documentation, `#[global_allocator] static NAME:
/// ::zeroizing_alloc::ZeroAlloc<::std::alloc::System> =
/// ::zeroizing_alloc::ZeroAlloc(::std::alloc::System);`, so a `cfg` cannot leave it
/// out of one build; and its package must depend on [`WIPING_ALLOCATOR_CRATE`], with
/// no other dependency taking its name. [`UNWIPED_CONTROL`] alone is excepted. A
/// root that cannot be read or parsed fails. Sorted; empty passes.
pub fn wiping_allocator(meta: &Value) -> Vec<String> {
    let empty = Vec::new();
    let workspace = members(meta);
    let root_dir = meta["workspace_root"].as_str().map(PathBuf::from);
    let strs = |v: &Value| -> Vec<String> {
        v.as_array()
            .unwrap_or(&empty)
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let mut problems = Vec::new();
    for package in meta["packages"].as_array().unwrap_or(&empty) {
        if !package["id"]
            .as_str()
            .is_some_and(|id| workspace.contains(id))
        {
            continue;
        }
        let name = package["name"].as_str().unwrap_or("a package");
        let deps = package["dependencies"].as_array().unwrap_or(&empty);
        let (crate_name, version) = WIPING_ALLOCATOR_CRATE;
        let approved = |d: &Value| {
            d["name"] == crate_name
                && d["rename"].is_null()
                && d["kind"].is_null()
                && d["req"] == version
                && d["source"]
                    .as_str()
                    .is_some_and(|s| s == "registry+https://github.com/rust-lang/crates.io-index")
        };
        // The name the crate is reached by in code: its rename, or its own name.
        let called = |d: &Value| {
            d["rename"]
                .as_str()
                .or(d["name"].as_str())
                .unwrap_or("")
                .replace('-', "_")
        };
        let has_allocator = deps.iter().any(approved)
            && !deps
                .iter()
                .any(|d| !approved(d) && called(d) == crate_name.replace('-', "_"));
        let unpublished = package["publish"].as_array().is_some_and(Vec::is_empty);
        for target in package["targets"].as_array().unwrap_or(&empty) {
            let kinds = strs(&target["kind"]);
            let types = strs(&target["crate_types"]);
            let built_only = kinds
                .iter()
                .all(|k| matches!(k.as_str(), "test" | "bench" | "custom-build"));
            let program = types
                .iter()
                .any(|t| matches!(t.as_str(), "bin" | "cdylib" | "staticlib"));
            if built_only || !program {
                continue;
            }
            let Some(root) = target["src_path"].as_str() else {
                problems.push(format!("{name} has a program with no root"));
                continue;
            };
            let (control_package, control_bin, control_root) = UNWIPED_CONTROL;
            let control = name == control_package
                && unpublished
                && target["name"] == control_bin
                && kinds == ["bin"]
                && root_dir.as_ref().is_some_and(|r| {
                    let expected = control_root
                        .split('/')
                        .fold(r.clone(), |p, part| p.join(part));
                    Path::new(root) == expected
                });
            if control {
                continue;
            }
            match std::fs::read_to_string(root) {
                Ok(source) if installs_wiping_allocator(&source) => {}
                Ok(_) => problems.push(format!("{root} does not install the wiping allocator")),
                Err(e) => problems.push(format!("{root}: {e}")),
            }
            if !has_allocator {
                problems.push(format!(
                    "{name} does not depend on {crate_name} {version} from crates.io by its own name"
                ));
            }
        }
    }
    problems.sort();
    problems.dedup();
    problems
}

/// Whether a program root installs [`WIPING_ALLOCATOR`] as [`wiping_allocator`] requires.
pub fn installs_wiping_allocator(source: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    let idents = |path: &syn::Path| -> Vec<String> {
        path.segments.iter().map(|s| s.ident.to_string()).collect()
    };
    // Absolute paths only: `::name` is an outside crate, never a local module.
    let system = |path: &syn::Path| {
        idents(path) == ["std", "alloc", "System"]
            && path.segments.iter().all(|s| s.arguments.is_none())
            && path.leading_colon.is_some()
    };
    let zero_alloc = |path: &syn::Path| {
        idents(path) == ["zeroizing_alloc", "ZeroAlloc"] && path.leading_colon.is_some()
    };
    // An `extern crate` binding the name would put another crate, or this one, behind it, raw
    // identifier or not (found in review: `extern crate self as r#zeroizing_alloc;`).
    if file.items.iter().any(|item| {
        use syn::ext::IdentExt;
        matches!(item, syn::Item::ExternCrate(e)
            if e.rename.as_ref().map_or(&e.ident, |(_, r)| r).unraw() == "zeroizing_alloc")
    }) {
        return false;
    }
    file.items.iter().any(|item| {
        let syn::Item::Static(s) = item else {
            return false;
        };
        // `#[global_allocator]` and nothing else but documentation: no `cfg`, `cfg_attr`
        // or anything else that could take it out of a build.
        let others: Vec<&syn::Attribute> = s
            .attrs
            .iter()
            .filter(|a| !(names(a.path(), "doc") && matches!(a.meta, syn::Meta::NameValue(_))))
            .collect();
        let attribute = matches!(&others[..], [a]
            if matches!(a.style, syn::AttrStyle::Outer)
                && names(a.path(), "global_allocator")
                && matches!(a.meta, syn::Meta::Path(_)));
        let ty = match &*s.ty {
            syn::Type::Path(t) if t.qself.is_none() && zero_alloc(&t.path) => {
                match &t.path.segments.last().map(|l| &l.arguments) {
                    Some(syn::PathArguments::AngleBracketed(args)) => matches!(
                        args.args.iter().collect::<Vec<_>>()[..],
                        [syn::GenericArgument::Type(syn::Type::Path(inner))]
                            if inner.qself.is_none() && system(&inner.path)
                    ),
                    _ => false,
                }
            }
            _ => false,
        };
        let value = match &*s.expr {
            syn::Expr::Call(call) if call.attrs.is_empty() => {
                matches!(&*call.func, syn::Expr::Path(f)
                    if f.attrs.is_empty() && f.qself.is_none() && zero_alloc(&f.path))
                    && matches!(call.args.iter().collect::<Vec<_>>()[..],
                        [syn::Expr::Path(a)] if a.attrs.is_empty() && a.qself.is_none() && system(&a.path))
            }
            _ => false,
        };
        attribute && ty && value && matches!(s.mutability, syn::StaticMutability::None)
    })
}

fn names(path: &syn::Path, name: &str) -> bool {
    use syn::ext::IdentExt;
    path.get_ident().is_some_and(|i| i.unraw() == name)
}

/// Whether a crate root has an inner `#![cfg(...)]`, read with syn.
fn has_crate_cfg(source: &str) -> bool {
    syn::parse_file(source).is_ok_and(|f| {
        f.attrs
            .iter()
            .any(|a| matches!(a.style, syn::AttrStyle::Inner(_)) && a.path().is_ident("cfg"))
    })
}

/// Whether a crate root forbids unsafe code with an inner attribute that the
/// compiler applies: `#![forbid(...)]` naming the lint `unsafe_code`, not under
/// `cfg_attr`. The file is parsed by `syn`, a complete Rust parser, so shebangs,
/// comments, raw strings, raw identifiers and raw lifetimes are read as Rust reads
/// them; text inside any of them is never taken for the attribute. A hand-written
/// lexer was tried first and each of four review rounds found a construct it
/// misread, so it was replaced. A file `syn` cannot parse counts as absent: the
/// check fails closed.
pub fn forbids_unsafe(source: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    file.attrs.iter().any(|a| {
        if !matches!(a.style, syn::AttrStyle::Inner(_)) || !names(a.path(), "forbid") {
            return false;
        }
        // `forbid(...)` only: rustc rejects `forbid[...]` and `forbid{...}` (found in
        // review), so neither may count.
        let syn::Meta::List(list) = &a.meta else {
            return false;
        };
        if !matches!(list.delimiter, syn::MacroDelimiter::Paren(_)) {
            return false;
        }
        let mut found = false;
        let parsed = list.parse_nested_meta(|meta| {
            if meta.input.peek(syn::Token![=]) {
                // `name = value`, such as `reason = "..."`: not a lint.
                meta.value()?.parse::<syn::Expr>()?;
            } else if names(&meta.path, "unsafe_code")
                && (meta.input.is_empty() || meta.input.peek(syn::Token![,]))
            {
                found = true;
            }
            Ok(())
        });
        parsed.is_ok() && found
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph(cc_kind: Value) -> Value {
        json!({
            "workspace_members": ["lib"],
            "packages": [
                {"id": "lib", "name": "qso-graph-trust", "version": "0.1.0", "source": null, "links": null, "targets": [{"kind": ["lib"]}]},
                {"id": "mid", "name": "middle", "version": "1.0.0", "source": CRATES_IO, "links": null, "targets": [{"kind": ["lib"]}]},
                {"id": "cc", "name": "cc", "version": "1.2.0", "source": CRATES_IO, "links": null, "targets": [{"kind": ["lib"]}]}
            ],
            "resolve": {"nodes": [
                {"id": "lib", "deps": [{"pkg": "mid", "dep_kinds": [{"kind": null}]}]},
                {"id": "mid", "deps": [{"pkg": "cc", "dep_kinds": [{"kind": cc_kind}]}]},
                {"id": "cc", "deps": []}
            ]}
        })
    }

    #[test]
    fn a_build_script_or_proc_macro_must_be_reviewed_by_name_and_version() {
        // Our own crate's build script or procedural macro is on our reviewed list;
        // an outside crate's is reviewed with the rest of it, through cargo-vet.
        let mut g = graph(json!("dev"));
        g["packages"][0]["targets"] = json!([{"kind": ["lib"]}, {"kind": ["custom-build"]}]);
        assert_eq!(
            no_c(&g, PROTECTED),
            vec!["qso-graph-trust 0.1.0 has a build script that has not been reviewed"]
        );
        g["packages"][0]["targets"] = json!([{"kind": ["proc-macro"]}]);
        assert_eq!(
            no_c(&g, PROTECTED),
            vec!["qso-graph-trust 0.1.0 has a procedural macro that has not been reviewed"]
        );
        let mut h = graph(json!("dev"));
        h["packages"][1]["targets"] = json!([{"kind": ["lib"]}, {"kind": ["custom-build"]}]);
        assert!(no_c(&h, PROTECTED).is_empty());
    }

    #[test]
    fn every_outside_crate_a_shipped_crate_needs_is_reviewed() {
        // A dependency of the command line, not the library, is held to the same
        // sources: crates.io, reviewed through cargo-vet (found in review).
        let mut g = graph(json!("dev"));
        g["packages"][0]["name"] = json!("qso-graph-trust-cli");
        assert!(unreviewed_in(&g, &["qso-graph-trust-cli"]).is_empty());
        g["packages"][1]["source"] = json!("git+https://example.invalid/middle");
        assert_eq!(
            unreviewed_in(&g, &["qso-graph-trust-cli"]),
            vec!["middle 1.0.0 is not a crates.io crate"]
        );
        assert_eq!(
            unreviewed_in(&g, &["gone"]),
            vec!["shipped crate gone is not a workspace member"]
        );
        // A path and a version together build something else once published
        // (found in review); our own shipped crates may be named so.
        let mut h = graph(json!("dev"));
        h["packages"][0]["name"] = json!("qso-graph-trust-cli");
        h["packages"][0]["dependencies"] = json!([
            {"name": "libc", "req": "=0.2.177", "path": "/x/crates/libc", "registry": null},
            {"name": "qso-graph-trust", "req": "^0.1.0", "path": "/x/crates/qso-graph-trust", "registry": null},
            {"name": "other", "req": "^1", "path": null, "registry": "https://example.invalid/index"}
        ]);
        let found = unreviewed_reviewing(
            &h,
            &["qso-graph-trust-cli", "qso-graph-trust"],
            TEST_REVIEWED,
        );
        assert!(found.contains(&"qso-graph-trust-cli depends on libc by both a path and a version: published, it would build the registry's".to_string()), "{found:?}");
        assert!(
            found.contains(
                &"qso-graph-trust-cli depends on other from another registry".to_string()
            ),
            "{found:?}"
        );
        assert!(
            !found.iter().any(|f| f.contains("on qso-graph-trust")),
            "{found:?}"
        );
        // The shipped crate's own build script is reviewed too (found in review).
        let mut k = graph(json!("dev"));
        k["packages"][0]["name"] = json!("qso-graph-trust-cli");
        k["packages"][0]["targets"] = json!([{"kind": ["bin"]}, {"kind": ["custom-build"]}]);
        assert!(
            unreviewed_reviewing(&k, &["qso-graph-trust-cli"], TEST_REVIEWED).contains(
                &"qso-graph-trust-cli 0.1.0 has a build script that has not been reviewed"
                    .to_string()
            )
        );
    }

    #[test]
    fn a_configuration_above_the_checkout_that_changes_compiling_is_found() {
        let t = |s: &str| weakening_keys(&table(s));
        assert_eq!(
            t("[build]\nrustflags = [\"--cap-lints=allow\"]\n"),
            vec!["build.rustflags"]
        );
        assert_eq!(
            t("[target.x86_64-unknown-linux-gnu]\nlinker = \"cc\"\n"),
            vec!["target.x86_64-unknown-linux-gnu.linker"]
        );
        assert_eq!(t("[env]\nX = \"1\"\n"), vec!["[env]"]);
        assert!(t("[net]\ngit-fetch-with-cli = true\n[build]\njobs = 4\n").is_empty());
    }

    #[test]
    fn a_crate_level_cfg_is_found() {
        assert!(has_crate_cfg("#![cfg(unix)]\n#![forbid(unsafe_code)]"));
        assert!(!has_crate_cfg(
            "#![forbid(unsafe_code)]\n#[cfg(unix)] fn f() {}"
        ));
    }

    #[test]
    fn a_protected_crate_outside_the_workspace_fails() {
        let mut g = graph(json!("dev"));
        g["workspace_members"] = json!([]);
        assert!(
            check(&g, PROTECTED)
                .contains(&"protected crate qso-graph-trust is not a workspace member".to_string()),
            "{:?}",
            check(&g, PROTECTED)
        );
    }

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// A consumer's build of the library: its own crate `app`, which turns on aws-lc-rs's `fips`
    /// feature, and the library from [`REPOSITORY`] at v0.1.0 and [`COMMIT`], down to AWS-LC's two
    /// builds.
    fn consumer_graph() -> Value {
        let ours = format!("git+{REPOSITORY}?tag=v0.1.0#{COMMIT}");
        json!({
            "workspace_members": ["app"],
            "packages": [
                {"id": "app", "name": "app", "version": "1.0.0", "source": null, "links": null, "targets": [{"kind": ["lib"]}],
                 "dependencies": [{"name": "aws-lc-rs", "kind": null, "features": ["fips"]}]},
                {"id": "lib", "name": "qso-graph-trust", "version": "0.1.0", "source": ours, "links": null, "targets": [{"kind": ["lib"]}]},
                {"id": "bind", "name": "qso-graph-trust-awslc", "version": "0.1.0", "source": ours, "links": null, "targets": [{"kind": ["lib"]}]},
                {"id": "rs", "name": "aws-lc-rs", "version": "1.18.1", "source": CRATES_IO, "links": null, "targets": [{"kind": ["lib"]}]},
                {"id": "sys", "name": "aws-lc-sys", "version": "0.45.0", "source": CRATES_IO, "links": "aws_lc_0_45_0", "targets": [{"kind": ["lib"]}]},
                {"id": "fips", "name": "aws-lc-fips-sys", "version": "0.14.2", "source": CRATES_IO, "links": "aws_lc_fips_0_14_2", "targets": [{"kind": ["lib"]}]}
            ],
            "resolve": {"nodes": [
                {"id": "app", "deps": [
                    {"pkg": "lib", "dep_kinds": [{"kind": null}]},
                    {"pkg": "rs", "dep_kinds": [{"kind": null}]}
                ]},
                {"id": "lib", "deps": [{"pkg": "bind", "dep_kinds": [{"kind": null}]}]},
                {"id": "bind", "deps": [
                    {"pkg": "rs", "dep_kinds": [{"kind": null}]},
                    {"pkg": "sys", "dep_kinds": [{"kind": null}]}
                ]},
                {"id": "rs", "deps": [
                    {"pkg": "sys", "dep_kinds": [{"kind": null}]},
                    {"pkg": "fips", "dep_kinds": [{"kind": null}]}
                ]},
                {"id": "sys", "deps": []},
                {"id": "fips", "deps": []}
            ]}
        })
    }

    /// The versions the consumer graph's library is reviewed with.
    fn consumer_reviewed() -> BTreeSet<(String, String)> {
        [
            ("qso-graph-trust", "0.1.0"),
            ("qso-graph-trust-awslc", "0.1.0"),
            ("aws-lc-rs", "1.18.1"),
            ("aws-lc-sys", "0.45.0"),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn a_consumer_builds_this_release_from_this_repository() {
        let g = consumer_graph();
        assert!(consumer_source(&g, COMMIT).is_empty());
        // PLANTED: another commit than the one the check runs from.
        let other = "f".repeat(40);
        assert_eq!(
            consumer_source(&g, &other),
            vec![
                format!(
                    "qso-graph-trust 0.1.0 is from git+{REPOSITORY}?tag=v0.1.0#{COMMIT}, not git+{REPOSITORY}?tag=v0.1.0#{other}"
                ),
                format!(
                    "qso-graph-trust-awslc 0.1.0 is from git+{REPOSITORY}?tag=v0.1.0#{COMMIT}, not git+{REPOSITORY}?tag=v0.1.0#{other}"
                ),
            ]
        );
        // PLANTED: a branch, a tag that is not the crate's version, crates.io, a path, a fork.
        for source in [
            json!(format!("git+{REPOSITORY}?branch=main#{COMMIT}")),
            json!(format!("git+{REPOSITORY}?tag=v0.1.1#{COMMIT}")),
            json!(CRATES_IO),
            Value::Null,
            json!(format!("git+{REPOSITORY}-fork?tag=v0.1.0#{COMMIT}")),
        ] {
            let mut h = consumer_graph();
            h["packages"][1]["source"] = source.clone();
            assert_eq!(consumer_source(&h, COMMIT).len(), 1, "{source}");
        }
        // PLANTED: two copies of the library.
        let mut h = consumer_graph();
        let copy = h["packages"][1].clone();
        h["packages"].as_array_mut().expect("packages").push(copy);
        assert_eq!(
            consumer_source(&h, COMMIT),
            vec!["qso-graph-trust is in the build 2 times, not once"]
        );
    }

    #[test]
    fn a_consumer_builds_only_the_reviewed_versions() {
        let g = consumer_graph();
        let reviewed = consumer_reviewed();
        assert!(consumer_versions(&g, &reviewed).is_empty());
        // PLANTED: the consumer's lock file resolves one of the library's dependencies otherwise.
        let mut h = consumer_graph();
        h["packages"][3]["version"] = json!("1.18.0");
        assert_eq!(
            consumer_versions(&h, &reviewed),
            vec!["aws-lc-rs 1.18.0 is not the version QG Trust's lock file holds"]
        );
        // PLANTED: the FIPS build without the consumer turning it on is the library's, and unreviewed.
        let mut h = consumer_graph();
        h["packages"][0]["dependencies"] = json!([]);
        assert_eq!(
            consumer_versions(&h, &reviewed),
            vec!["aws-lc-fips-sys 0.14.2 is not the version QG Trust's lock file holds"]
        );
    }

    #[test]
    fn a_consumer_brings_no_c_but_aws_lc() {
        let g = consumer_graph();
        assert!(consumer_turns_on_fips(&g));
        assert!(consumer_no_c(&g).is_empty(), "{:?}", consumer_no_c(&g));
        // PLANTED: the consumer does not turn the FIPS build on, so it is the library's C.
        let mut h = consumer_graph();
        h["packages"][0]["dependencies"] =
            json!([{"name": "aws-lc-rs", "kind": null, "features": []}]);
        assert!(!consumer_turns_on_fips(&h));
        assert_eq!(
            consumer_no_c(&h),
            vec!["aws-lc-fips-sys links the native library aws_lc_fips_0_14_2"]
        );
        // PLANTED: the library reaches the FIPS build other than through aws-lc-rs.
        let mut h = consumer_graph();
        h["resolve"]["nodes"][1]["deps"]
            .as_array_mut()
            .expect("deps")
            .push(json!({"pkg": "fips", "dep_kinds": [{"kind": null}]}));
        assert_eq!(
            consumer_no_c(&h),
            vec![
                "qso-graph-trust depends on aws-lc-fips-sys: only aws-lc-rs may",
                "qso-graph-trust depends on aws-lc-fips-sys: only qso-graph-trust-awslc may",
            ]
        );
        // PLANTED: the library from somewhere else.
        let mut h = consumer_graph();
        h["packages"][1]["source"] =
            json!("git+https://example.invalid/qso-graph-trust?tag=v0.1.0#0");
        assert_eq!(
            consumer_no_c(&h),
            vec![
                format!("protected crate qso-graph-trust is not from {REPOSITORY}"),
                "qso-graph-trust 0.1.0 is not a crates.io crate".to_string(),
            ]
        );
        // This workspace's own build never takes the FIPS build, whatever turns it on.
        let mut h = consumer_graph();
        h["workspace_members"] = json!(["lib", "bind"]);
        h["packages"][1]["source"] = Value::Null;
        h["packages"][2]["source"] = Value::Null;
        assert_eq!(
            no_c(&h, PROTECTED),
            vec!["aws-lc-fips-sys links the native library aws_lc_fips_0_14_2"]
        );
    }

    /// The test graph's outside crates, reviewed, so each test sees only its own finding.
    const TEST_REVIEWED: &[(&str, &str, &str)] =
        &[("middle", "1.0.0", "test"), ("cc", "1.2.0", "test")];

    fn check(g: &Value, protected: &[&str]) -> Vec<String> {
        no_c_reviewing(g, protected, TEST_REVIEWED, None)
    }

    #[test]
    fn an_outside_crate_must_be_from_crates_io_and_reviewed() {
        // From crates.io: the check passes, and cargo-vet reviews it.
        let mut g = graph(json!("dev"));
        assert!(no_c(&g, PROTECTED).is_empty());
        g["packages"][1]["source"] = json!("git+https://example.invalid/middle");
        assert_eq!(
            check(&g, PROTECTED),
            vec!["middle 1.0.0 is not a crates.io crate"]
        );
    }

    #[test]
    fn only_os_bindings_may_link_or_declare_foreign_functions() {
        let mut g = graph(json!("dev"));
        g["packages"][1]["name"] = json!("libc");
        g["packages"][1]["links"] = json!("c");
        assert!(no_c(&g, PROTECTED).is_empty());
        g["packages"][1]["name"] = json!("not-an-os-binding");
        assert_eq!(
            no_c(&g, PROTECTED),
            vec!["not-an-os-binding links the native library c"]
        );
    }

    #[test]
    fn secret_service_crypto_is_limited_to_the_reviewed_session_edges() {
        let mut g = graph(json!(null));
        g["packages"][1]["name"] = json!("secret-service");
        g["packages"][1]["version"] = json!("5.2.0");
        g["packages"][2]["name"] = json!("aes");
        g["packages"][2]["version"] = json!("0.9.4");
        g["resolve"]["nodes"][1]["features"] = json!(["crypto-rust"]);
        assert!(unreviewed_in(&g, PROTECTED).is_empty());
        // PLANTED: the transport exception grants no native-link privilege.
        g["packages"][1]["links"] = json!("planted_native");
        assert!(
            no_c(&g, PROTECTED)
                .iter()
                .any(|p| p.contains("links the native library planted_native"))
        );
        g["packages"][1]["links"] = Value::Null;
        assert!(no_c(&g, PROTECTED).is_empty());
        // PLANTED: a signer/certificate handler cannot borrow the algorithm exception.
        g["packages"][1]["name"] = json!("certificate-handler");
        assert!(
            unreviewed_in(&g, PROTECTED)
                .iter()
                .any(|p| p.contains("outside Secret Service session transport"))
        );
        g["packages"][1]["name"] = json!("secret-service");
        assert!(unreviewed_in(&g, PROTECTED).is_empty());
        // PLANTED: direct use, including from the CLI/TLS path, remains forbidden.
        let edge = json!({"pkg": "cc", "dep_kinds": [{"kind": null}]});
        g["resolve"]["nodes"][0]["deps"]
            .as_array_mut()
            .expect("deps")
            .push(edge);
        assert!(
            unreviewed_in(&g, PROTECTED)
                .iter()
                .any(|p| p.contains("qso-graph-trust 0.1.0 uses aes"))
        );
        g["packages"][0]["name"] = json!("qso-graph-trust-cli");
        assert!(
            unreviewed_in(&g, &["qso-graph-trust-cli"])
                .iter()
                .any(|p| p.contains("outside Secret Service session transport"))
        );
        g["packages"][0]["name"] = json!("qso-graph-trust");
        g["resolve"]["nodes"][0]["deps"]
            .as_array_mut()
            .expect("deps")
            .pop();
        assert!(unreviewed_in(&g, PROTECTED).is_empty());
        // PLANTED: transport/algorithm upgrades and another crypto feature need new review.
        for (package, version) in [(1, "5.3.0"), (2, "0.9.5")] {
            let original = g["packages"][package]["version"].clone();
            g["packages"][package]["version"] = json!(version);
            assert!(!unreviewed_in(&g, PROTECTED).is_empty());
            g["packages"][package]["version"] = original;
            assert!(unreviewed_in(&g, PROTECTED).is_empty());
        }
        g["resolve"]["nodes"][1]["features"] = json!(["crypto-rust", "crypto-openssl"]);
        assert!(!unreviewed_in(&g, PROTECTED).is_empty());
        g["resolve"]["nodes"][1]["features"] = json!(["crypto-rust"]);
        assert!(unreviewed_in(&g, PROTECTED).is_empty());
    }

    #[test]
    fn secret_service_api_is_only_available_to_the_credential_backend() {
        let dir = fresh_temp_dir("qgt-session-transport-policy").expect("temporary directory");
        let backend = dir.join("src/store/keys/os.rs");
        std::fs::create_dir_all(backend.parent().expect("parent")).expect("mkdir");
        let approved = "use secret_service::{EncryptionType, blocking::SecretService};";
        std::fs::write(&backend, approved).expect("approved transport import");
        let mut g = graph(json!("dev"));
        g["packages"][0]["manifest_path"] = json!(dir.join("Cargo.toml"));
        assert!(no_network(&g).is_empty());
        // PLANTED: even the connection API cannot be used from signing/certificate code.
        let signer = dir.join("src/signing.rs");
        std::fs::write(&signer, approved).expect("plant another use");
        assert!(
            no_network(&g)
                .iter()
                .any(|p| p.contains("signing.rs uses Secret Service"))
        );
        std::fs::remove_file(signer).expect("remove plant");
        assert!(no_network(&g).is_empty());
        for planted in [
            "use secret_service::session::encrypt;",
            "#[cfg(any())] fn sign() { secret_service::session::decrypt(); }",
            "use secret_service as crypto;",
            "use secret_service::*;",
            "use secret_service::{blocking as b};",
            "extern crate secret_service as transport;",
        ] {
            std::fs::write(&backend, planted).expect("plant crypto API");
            assert!(
                no_network(&g)
                    .iter()
                    .any(|p| p.contains("outside the permitted transport API")),
                "missed {planted}"
            );
            std::fs::write(&backend, approved).expect("remove plant");
            assert!(no_network(&g).is_empty());
        }
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn foreign_declaration_exceptions_require_the_exact_crate_version_and_file() {
        for (name, version, file, _) in FOREIGN_DECLARATIONS {
            assert!(!OS_BINDINGS.contains(name));
            let dir = fresh_temp_dir("qgt-foreign-declaration").expect("fresh directory");
            let path = dir.join(file);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, "extern \"C\" { fn planted(); }").expect("plant");
            let mut g = graph(json!("dev"));
            g["packages"][1]["name"] = json!(name);
            g["packages"][1]["version"] = json!(version);
            g["packages"][1]["manifest_path"] = json!(dir.join("Cargo.toml"));
            assert!(no_c(&g, PROTECTED).is_empty());

            // PLANTED: the same file in another version or crate must fail, and passes again
            // only when the reviewed identity is restored.
            for (field, value, restore) in [
                ("version", "99.0.0", *version),
                ("name", "planted-unreviewed", *name),
            ] {
                g["packages"][1][field] = json!(value);
                assert_eq!(no_c(&g, PROTECTED).len(), 1);
                g["packages"][1][field] = json!(restore);
                assert!(no_c(&g, PROTECTED).is_empty());
            }

            // PLANTED: a new file in the allowed crate and version is still scanned.
            let extra = dir.join("src/planted.rs");
            std::fs::copy(&path, &extra).expect("plant another file");
            assert_eq!(
                no_c(&g, PROTECTED),
                [format!(
                    "{name} {version}: src/planted.rs declares foreign functions"
                )]
            );
            std::fs::remove_file(extra).expect("remove plant");
            assert!(no_c(&g, PROTECTED).is_empty());

            // PLANTED: even in the reviewed file a new native link is refused.
            std::fs::write(
                &path,
                "#[link(name = \"planted\")] extern \"C\" { fn planted(); }",
            )
            .expect("plant link");
            assert_eq!(
                no_c(&g, PROTECTED),
                [format!("{name} {version}: {file} has a #[link] attribute")]
            );
            std::fs::write(&path, "extern \"C\" { fn planted(); }").expect("remove link");
            assert!(no_c(&g, PROTECTED).is_empty());
            let native = dir.join("src/planted.c");
            std::fs::write(&native, "void planted(void) {}").expect("plant native source");
            assert_eq!(no_c(&g, PROTECTED).len(), 1);
            std::fs::remove_file(native).expect("remove native source");
            assert!(no_c(&g, PROTECTED).is_empty());
            std::fs::remove_dir_all(dir).expect("cleanup");
        }
    }

    /// The probe compiles beside whatever a valid library declares, so only the
    /// lints can refuse it: a library with its own `mod core` once broke it (found in
    /// review), as would one without the implicit prelude.
    #[test]
    fn the_canary_probe_compiles_beside_any_library_and_only_lints_refuse_it() {
        let dir = fresh_temp_dir("qso-graph-trust-probe").expect("a fresh directory");
        for (n, library) in [
            "pub mod core {}\n",
            "#![no_implicit_prelude]\n",
            "pub mod ptr {}\npub mod core { pub mod ptr {} }\n",
            // Its own name taken, and the type it reads shadowed (round 39).
            "pub fn qgt_canary() {}\n",
            "#[allow(non_camel_case_types)]\npub struct u8;\n",
            // `::core` itself taken over by a crate alias (round 40).
            "pub extern crate self as core;\n",
        ]
        .iter()
        .enumerate()
        {
            let src = dir.join(format!("lib{n}.rs"));
            std::fs::write(&src, format!("{library}{CANARY_PROBE}")).expect("write");
            let rustc = |flag: &str| {
                Command::new("rustc")
                    .args([
                        "--edition",
                        "2024",
                        "--crate-type",
                        "lib",
                        "--emit",
                        "metadata",
                    ])
                    .arg("--out-dir")
                    .arg(&dir)
                    .arg(flag)
                    .arg(&src)
                    .output()
                    .expect("rustc runs")
            };
            let capped = rustc("--cap-lints=allow");
            assert!(
                capped.status.success(),
                "{library:?}: {}",
                String::from_utf8_lossy(&capped.stderr)
            );
            let refused = rustc("-Funsafe_code");
            assert!(!refused.status.success(), "{library:?}: not refused");
            assert!(
                String::from_utf8_lossy(&refused.stderr).contains("usage of an `unsafe` block"),
                "{library:?}: {}",
                String::from_utf8_lossy(&refused.stderr)
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn foreign_blocks_and_assembly_are_found_as_tokens() {
        let scan = |s: &str| native_tokens(s.parse().expect("tokens"));
        assert_eq!(
            scan("extern \"C\" { fn f(); }"),
            vec!["declares foreign functions"]
        );
        assert_eq!(
            scan("unsafe extern { fn f(); }"),
            vec!["declares foreign functions"]
        );
        assert_eq!(
            scan("#[link(name = \"z\")] extern {}"),
            vec!["has a #[link] attribute", "declares foreign functions"]
        );
        assert_eq!(
            scan("core::arch::global_asm! { \"nop\" }"),
            vec!["holds assembly"]
        );
        // Rust calling Rust is not a native binding.
        assert!(scan("extern \"Rust\" { fn f(); }").is_empty());
        // `assert![link]` is a macro call, not a `#![link]` attribute (found in
        // review); `#![link]` and `#[link]` still are.
        assert!(scan("pub fn f(link: bool) { assert![link]; }").is_empty());
        assert_eq!(
            scan("#![link(name = \"z\")]"),
            vec!["has a #[link] attribute"]
        );
        // `r#extern` is an identifier, not the keyword (found in review);
        // `r#asm!` is still the asm macro, and `#[r#link]` still the attribute.
        assert!(scan("pub struct r#extern { pub value: u8 }").is_empty());
        assert_eq!(scan("r#asm!(\"nop\");"), vec!["holds assembly"]);
        assert_eq!(
            scan("#[r#link(name = \"z\")] extern \"C\" {}"),
            vec!["has a #[link] attribute", "declares foreign functions"]
        );
        // A foreign ABI on a function we define, and words in strings, are not bindings.
        assert!(
            scan("pub extern \"C\" fn f() {} const S: &str = \"extern \\\"C\\\" {\";").is_empty()
        );
    }

    /// lib -> (binding) -> aws-lc-sys, with aws-lc-sys building through cc and needing `rt` at
    /// run time. `via` names the crate between the library and the provider.
    fn provider_graph(via: &str) -> Value {
        json!({
            "workspace_members": ["lib", "bind"],
            "packages": [
                {"id": "lib", "name": "qso-graph-trust", "version": "0.1.0", "source": null, "links": null, "targets": [{"kind": ["lib"]}]},
                {"id": "bind", "name": via, "version": "0.1.0", "source": null, "links": null, "targets": [{"kind": ["lib"]}]},
                {"id": "aws", "name": "aws-lc-sys", "version": "0.45.0", "source": CRATES_IO, "links": "aws_lc_0_45_0", "targets": [{"kind": ["lib"]}, {"kind": ["custom-build"]}]},
                {"id": "cc", "name": "cc", "version": "1.11.0", "source": CRATES_IO, "links": null, "targets": [{"kind": ["lib"]}]},
                {"id": "rt", "name": "runtime", "version": "1.0.0", "source": CRATES_IO, "links": null, "targets": [{"kind": ["lib"]}]}
            ],
            "resolve": {"nodes": [
                {"id": "lib", "deps": [{"pkg": "bind", "dep_kinds": [{"kind": null}]}]},
                {"id": "bind", "deps": [{"pkg": "aws", "dep_kinds": [{"kind": null}]}]},
                {"id": "aws", "deps": [{"pkg": "cc", "dep_kinds": [{"kind": "build"}]}, {"pkg": "rt", "dep_kinds": [{"kind": null}]}]},
                {"id": "cc", "deps": []},
                {"id": "rt", "deps": []}
            ]}
        })
    }

    #[test]
    fn the_crypto_provider_is_allowed_only_through_the_binding() {
        // Through the binding: the provider's C, links and build tools are allowed.
        assert!(check(&provider_graph(UNSAFE_BINDING), PROTECTED).is_empty());
        // PLANTED: any other crate depending on it is refused, so AWS-LC's C is reached only there.
        assert_eq!(
            check(&provider_graph("middle"), PROTECTED),
            vec!["middle depends on aws-lc-sys: only qso-graph-trust-awslc may"]
        );
        // PLANTED: what the provider needs at run time is still checked: a native link there fails.
        let mut g = provider_graph(UNSAFE_BINDING);
        g["packages"][4]["links"] = json!("evil");
        assert_eq!(
            check(&g, PROTECTED),
            vec!["runtime links the native library evil"]
        );
        // PLANTED: AWS-LC's safe API is the provider too, and also reached only through the binding:
        // through it, aws-lc-rs may depend on aws-lc-sys; a crate around the binding may not use it.
        let mut safe = provider_graph(UNSAFE_BINDING);
        safe["packages"].as_array_mut().expect("packages").push(
            json!({"id": "rs", "name": "aws-lc-rs", "version": "1.18.1", "source": CRATES_IO, "links": "aws_lc_rs_1_18_1_sys", "targets": [{"kind": ["lib"]}]}),
        );
        safe["resolve"]["nodes"]
            .as_array_mut()
            .expect("nodes")
            .push(json!({"id": "rs", "deps": [{"pkg": "aws", "dep_kinds": [{"kind": null}]}]}));
        safe["resolve"]["nodes"][1]["deps"]
            .as_array_mut()
            .expect("deps")
            .push(json!({"pkg": "rs", "dep_kinds": [{"kind": null}]}));
        assert!(check(&safe, PROTECTED).is_empty());
        let mut around = safe.clone();
        around["resolve"]["nodes"][0]["deps"]
            .as_array_mut()
            .expect("deps")
            .push(json!({"pkg": "rs", "dep_kinds": [{"kind": null}]}));
        assert_eq!(
            check(&around, PROTECTED),
            vec!["qso-graph-trust depends on aws-lc-rs: only qso-graph-trust-awslc may"]
        );
        // PLANTED: a crate of another name with the provider's links is not the provider.
        let mut h = provider_graph(UNSAFE_BINDING);
        h["packages"][2]["name"] = json!("aws-lc-sys-lookalike");
        assert!(
            check(&h, PROTECTED)
                .iter()
                .any(|p| p.contains("links the native library aws_lc_0_45_0"))
        );
    }

    #[test]
    fn the_binding_must_carry_exactly_its_own_lints() {
        let with = |lints: &str| -> toml::Table {
            toml::from_str(&format!("[package]\nname = \"x\"\n[lints.{lints}")).expect("toml")
        };
        let exact: toml::Table = toml::from_str(&format!(
            "[lints]\n{}",
            BINDING_LINTS
                .replace("[rust]", "[lints.rust]")
                .replace("[clippy]", "[lints.clippy]")
        ))
        .expect("toml");
        assert!(has_binding_lints(&exact));
        // PLANTED: weakened (unsafe allowed), one missing, or the workspace's instead.
        assert!(!has_binding_lints(&with(
            "rust]\nunsafe_code = \"allow\"\n"
        )));
        let mut missing = exact.clone();
        missing["lints"]["clippy"]
            .as_table_mut()
            .expect("clippy")
            .remove("undocumented_unsafe_blocks");
        assert!(!has_binding_lints(&missing));
        assert!(!has_binding_lints(
            &toml::from_str("[lints]\nworkspace = true\n").expect("toml")
        ));
    }

    #[test]
    fn a_build_script_compiling_c_two_levels_down_is_caught() {
        let problems = check(&graph(json!("build")), PROTECTED);
        assert_eq!(problems, vec!["middle builds native code through cc"]);
    }

    #[test]
    fn a_dev_dependency_is_not_shipped_so_not_caught() {
        assert!(check(&graph(json!("dev")), PROTECTED).is_empty());
    }

    #[test]
    fn a_missing_protected_crate_fails_rather_than_checking_nothing() {
        let problems = check(&graph(json!("build")), &["renamed"]);
        assert_eq!(
            problems,
            vec!["protected crate renamed is not in this workspace"]
        );
    }

    #[test]
    fn the_attribute_must_be_real_code() {
        assert!(forbids_unsafe(
            "//! doc\n#![forbid(unsafe_code)]\nfn f() {}"
        ));
        assert!(!forbids_unsafe("// #![forbid(unsafe_code)] is required\n"));
        assert!(!forbids_unsafe("#![deny(unsafe_code)]\n"));
    }

    #[test]
    fn an_attribute_hidden_in_a_comment_or_string_is_not_the_attribute() {
        assert!(!forbids_unsafe(
            "/*\n#![forbid(unsafe_code)]\n*/\npub fn f() {}"
        ));
        assert!(!forbids_unsafe(
            "/* outer /* inner */\n#![forbid(unsafe_code)]\n*/"
        ));
        assert!(!forbids_unsafe(
            "pub const S: &str = \"\n#![forbid(unsafe_code)]\n\";"
        ));
        assert!(!forbids_unsafe("fn f() {}\n#![forbid(unsafe_code)]\n"));
        assert!(!forbids_unsafe("/* never closed\n#![forbid(unsafe_code)]"));
    }

    #[test]
    fn tricks_found_by_the_second_review_are_not_the_attribute() {
        // A raw string whose text looks like an attribute (found in review).
        assert!(!forbids_unsafe(
            "#![doc = r#\"\"\n]\n#![forbid(unsafe_code)]\n\"#]\npub fn f() {}"
        ));
        // Brackets inside a comment inside an attribute.
        assert!(!forbids_unsafe(
            "#![doc = \"x\" /* ] */]\npub fn f() {}\n#![forbid(unsafe_code)]"
        ));
        assert!(!forbids_unsafe(
            "#![cfg_attr(any(), doc = \"/*]\"\n)] fn f() {} /* #![forbid(unsafe_code)] */"
        ));
        // The lint's name in a comment or a reason, not as the lint.
        assert!(!forbids_unsafe("#![forbid(/*,unsafe_code,*/ dead_code)]"));
        assert!(!forbids_unsafe(
            "#![forbid(dead_code, reason = \",unsafe_code,\")]"
        ));
        assert!(!forbids_unsafe("#![forbid(unsafe_code = 1)]"));
        assert!(!forbids_unsafe("#![cfg_attr(test, forbid(unsafe_code))]"));
        // Char and byte literals don't derail it, either way.
        assert!(forbids_unsafe(
            "#![doc = '[']\n#![doc = b']']\n#![forbid(unsafe_code)]"
        ));
        assert!(forbids_unsafe(
            "#![doc = br##\"]\"#\"##]\n#![forbid(unsafe_code)]"
        ));
        assert!(forbids_unsafe(
            "#![forbid(unsafe_code, reason = \"QGT holds keys\")]"
        ));
    }

    #[test]
    fn tricks_found_by_the_third_review_are_not_the_attribute() {
        // `#!` then a comment then `[` is an attribute, not a shebang.
        assert!(!forbids_unsafe(
            r##"#! /*
#![forbid(unsafe_code)]
*/ [allow(dead_code)]
"##
        ));
        // A literal's suffix is not a raw-string prefix: `""r` then a plain string.
        assert!(!forbids_unsafe(
            r##"#![cfg_attr(any(), arbitrary(""r"\"))]
#![forbid(unsafe_code)]
"))]
"##
        ));
        // A real shebang is still passed over, and a suffixed literal still lexes.
        assert!(forbids_unsafe(
            "#!/usr/bin/env cargo\n#![forbid(unsafe_code)]"
        ));
        assert!(forbids_unsafe(
            "#![doc = \"x\"suffix]\n#![forbid(unsafe_code)]"
        ));
    }

    #[test]
    fn a_raw_identifier_is_one_token() {
        // `r#r` is a raw identifier; the string after it is ordinary (found in review).
        assert!(!forbids_unsafe(
            r##"#![cfg_attr(any(), arbitrary(r#r"\"))]
#![forbid(unsafe_code)]
"))]
pub fn proof() {}
"##
        ));
        assert!(forbids_unsafe("#![doc(r#type)]\n#![forbid(unsafe_code)]"));
        // Not Rust: fails closed.
        assert!(!forbids_unsafe("#![doc(r##x)]\n#![forbid(unsafe_code)]"));
    }

    #[test]
    fn a_raw_lifetime_is_one_token() {
        // `'r#r` is a raw lifetime; the string after it is ordinary (found in review).
        assert!(!forbids_unsafe(
            r##"#![cfg_attr(any(), arbitrary('r#r"\"))]
#![forbid(unsafe_code)]
"))]
pub fn proof() {}
"##
        ));
    }

    #[test]
    fn only_parentheses_make_a_lint_list() {
        assert!(!forbids_unsafe("#![forbid{unsafe_code}]"));
        assert!(!forbids_unsafe("#![forbid[unsafe_code]]"));
        assert!(!forbids_unsafe("#![forbid = \"unsafe_code\"]"));
    }

    #[test]
    fn only_lint_levels_are_allowed_as_flags() {
        for f in [
            "",
            "-D warnings",
            "-Dwarnings",
            "-W clippy::all",
            "-A dead_code",
            "--deny=warnings",
        ] {
            assert!(flags_allowed(f), "{f}");
        }
        for f in [
            "--cap-lints=allow",
            "-D warnings --cap-lints warn",
            "-A unsafe_code",
            "-Aunsafe_code",
            "--allow=unsafe_code",
            "-W unsafe_code",
            "--force-warn unsafe_code",
            "-D warnings\u{1f}--cap-lints=allow",
            "@/tmp/ci.rsp",
            "-l static=z",
            "-lstatic=z",
            "-L /opt/lib",
            "-C link-arg=-lz",
            "-Zunstable-options",
            "-D",
        ] {
            assert!(!flags_allowed(f), "{f}");
        }
    }

    #[test]
    fn a_different_compiler_wrapper_or_linker_is_refused() {
        let env = |pairs: &[(&str, &str)]| {
            env_problems(pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())))
        };
        assert!(
            env(&[
                ("RUSTFLAGS", "-D warnings"),
                ("CARGO_TARGET_DIR", "/t"),
                ("CARGO_BUILD_JOBS", "4")
            ])
            .is_empty()
        );
        for var in [
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
        ] {
            assert_eq!(env(&[(var, "/x")]).len(), 1, "{var}");
        }
        assert_eq!(env(&[("RUSTFLAGS", "@/tmp/ci.rsp")]).len(), 1);
        // Any case, as Windows reads them, and the bootstrap switch (found in review).
        assert_eq!(env(&[("rustflags", "-l winmm")]).len(), 1);
        assert_eq!(env(&[("Rustc_Wrapper", "/x")]).len(), 1);
        assert_eq!(env(&[("RUSTC_BOOTSTRAP", "1")]).len(), 1);
    }

    #[test]
    fn unsafe_is_found_whatever_would_compile_it() {
        let scan = |s: &str| unsafe_tokens(s.parse().expect("tokens"));
        // Code no CI build compiles is still code (found in review).
        assert_eq!(
            scan(
                "#[cfg(not(debug_assertions))] pub fn f() -> u8 { unsafe { core::ptr::read(&7) } }"
            ),
            vec!["uses unsafe"]
        );
        assert!(scan("macro_rules! m { () => { unsafe {} } }").contains(&"uses unsafe"));
        assert_eq!(
            scan("#[unsafe(no_mangle)] pub fn f() {}"),
            vec!["uses unsafe"]
        );
        assert_eq!(scan("include!(\"../elsewhere.rs\");"), vec!["uses include"]);
        // A module from a file the scan would not read (found in review).
        assert_eq!(
            scan("#[cfg(not(debug_assertions))] #[path = \"release.inc\"] mod release;"),
            vec!["uses #[path]"]
        );
        assert!(scan("let path = [1]; let v = [path];").is_empty());
        // A binding inside an array is not an attribute (found in review).
        assert!(scan("pub fn paths() -> [u8; 1] { [{ let path = 1; path }] }").is_empty());
        // Comparisons are not assignments (found in review).
        assert!(scan("pub fn f(path: u8) -> bool { [path == 0][0] }").is_empty());
        assert!(scan("let v = [match x { path => 1 }];").is_empty());
        // Found in review: a raw `path`, and an attribute named by a macro variable.
        assert_eq!(
            scan("#[r#path = \"payload.inc\"] mod hidden;"),
            vec!["uses #[path]"]
        );
        assert!(
            scan("macro_rules! m { ($a:ident) => { #[$a = \"payload.inc\"] mod hidden; } }")
                .contains(&"builds an attribute from a macro variable")
        );
        // The # passed into a macro separately (found in review).
        let passed = scan(
            "macro_rules! load { ($h:tt [$i:ident]) => { $h [path = \"hidden.md\"] pub mod hidden; }; } load!(#[doc]);",
        );
        // Caught as a macro of our own, which the workspace may not define.
        assert!(passed.contains(&"defines a macro"), "{passed:?}");
        assert!(
            scan("macro_rules! m { ($h:tt $a:ident) => { $h [$a = \"x\"] mod y; } }")
                .contains(&"builds an attribute from a macro variable")
        );
        // Ordinary macro brackets are not attributes.
        assert_eq!(
            scan("macro_rules! v { ($($x:expr),*) => { [$($x),*] } }"),
            vec!["defines a macro"]
        );
        // A feature switched on only in some configurations (found in review).
        assert!(
            scan("#![cfg_attr(not(debug_assertions), feature(decl_macro))]")
                .contains(&"enables an unstable feature")
        );
        // Selecting a Cargo feature is not enabling an unstable one.
        assert!(scan("#[cfg(feature = \"std\")] fn f() {} #[cfg_attr(feature = \"x\", derive(Debug))] struct S;").is_empty());
        // Rust in a string a derive macro parses (found in review).
        let bound = scan(
            "#[serde(bound(deserialize = \"[(); unsafe { core::ptr::read(&7usize) }]: Sized\"))] pub struct P;",
        );
        assert!(bound.contains(&"uses unsafe"), "{bound:?}");
        // Prose in Rust's own attributes is not code (found in review).
        assert!(
            scan("#[must_use = \"include this value in the report\"] pub fn f() -> usize { 0 }")
                .is_empty()
        );
        assert!(scan("#[deprecated(note = \"use the unsafe-free API\")] pub fn g() {}").is_empty());
        // Raw spellings of the same names (round 34).
        assert!(scan("#[r#must_use = \"include this value\"] pub fn r() -> u8 { 0 }").is_empty());
        assert!(
            scan("#[r#cfg_attr(all(), must_use = \"include this value\")] pub fn s() -> u8 { 0 }")
                .is_empty()
        );
        // Inside cfg_attr too, while a wrapped derive helper is still read (round 33).
        assert!(
            scan("#[cfg_attr(all(), must_use = \"include this value\")] pub fn p() -> u8 { 0 }")
                .is_empty()
        );
        assert!(scan("#[cfg_attr(feature = \"x\", serde(bound = \"[(); unsafe { 0 }]: Sized\"))] struct Q;").contains(&"uses unsafe"));
        assert!(
            scan("#[allow(dead_code, reason = \"asm! is mentioned here\")] fn h() {}").is_empty()
        );
        // Every built-in attribute whose string is a name, a number or a reason
        // (found in review, debugger_visualizer; the rest from the Rust
        // Reference's index of built-in attributes, so the class is closed).
        for attr in [
            "#![debugger_visualizer(gdb_script_file = \"unsafe.md\")]",
            "#![r#debugger_visualizer(gdb_script_file = \"unsafe.md\")]",
            "#![cfg_attr(all(), debugger_visualizer(gdb_script_file = \"unsafe.md\"))]",
            "#![crate_name = \"unsafe_free\"]",
            "#![crate_type = \"lib\"]",
            "#![recursion_limit = \"256\"]",
            "#![type_length_limit = \"1048576\"]",
            "#![windows_subsystem = \"console\"]",
            "#[ignore = \"needs unsafe hardware\"] fn t() {}",
            "#[should_panic(expected = \"unsafe input\")] fn u() {}",
            "#[target_feature(enable = \"avx2\")] fn v() {}",
        ] {
            assert!(scan(attr).is_empty(), "{attr}: {:?}", scan(attr));
        }
        // Prose in a doc comment is not code.
        assert!(
            scan("/// Holds no unsafe code; see include! and asm! in the docs.\npub struct P;")
                .is_empty()
        );
        // The unstable `macro` and any unstable feature (found in review).
        let decl = scan(
            "#![feature(decl_macro, macro_metavar_expr_concat)] macro read_value() { ${concat(un, safe)} { 7 } }",
        );
        assert!(decl.contains(&"defines a macro"), "{decl:?}");
        assert!(decl.contains(&"enables an unstable feature"), "{decl:?}");
        // A macro of our own is refused outright (found in review).
        assert!(
            scan(
                "macro_rules! load { ($h:tt [$i:ident] $a:meta) => { $h [$a] pub mod hidden; }; }"
            )
            .contains(&"defines a macro")
        );
        // A # assembled with brackets by a macro (found in review).
        let assembled = scan(
            "macro_rules! load { ($a:tt) => { # $a pub mod hidden; }; } load!([path = \"hidden.md\"]);",
        );
        assert!(
            assembled.contains(&"has a # that does not begin an attribute"),
            "{assembled:?}"
        );
        assert!(
            scan("m!(#, [path = \"x\"]);").contains(&"has a # that does not begin an attribute")
        );
        // Attributes, inner and outer, raw strings and raw identifiers are not dangling.
        assert!(
            scan("#![forbid(unsafe_code)] #[derive(Debug)] struct S; const R: &str = r#\"x\"#;")
                .is_empty()
        );
        // Inside cfg_attr (found in review).
        assert_eq!(
            scan(
                "macro_rules! m { ($a:ident) => { #[cfg_attr(not(debug_assertions), $a = \"hidden.md\")] mod hidden; } }"
            ),
            vec![
                "defines a macro",
                "builds an attribute from a macro variable"
            ]
        );
        // Inside cfg_attr (found in review).
        assert_eq!(
            scan("#[cfg_attr(not(debug_assertions), path = \"release.inc\")] mod release;"),
            vec!["uses #[path]"]
        );
        // Raw identifiers, aliases and any delimiter (found in review).
        assert_eq!(scan("r#include!(\"payload.txt\");"), vec!["uses include"]);
        assert_eq!(
            scan("use core::include as load; load!(\"payload.txt\");"),
            vec!["uses include"]
        );
        assert_eq!(
            scan("#[cfg(not(debug_assertions))] core::arch::global_asm! { \".byte 0\" }"),
            vec!["uses global_asm"]
        );
        assert_eq!(scan("fn f() { r#unsafe { } }"), vec!["uses unsafe"]);
        // Words in strings and comments are not tokens.
        assert!(scan("// unsafe\nconst S: &str = \"unsafe { }\";").is_empty());
        assert!(scan("const B: &[u8] = include_bytes!(\"x.bin\");").is_empty());
    }

    #[test]
    fn only_the_pinned_stable_compiler_passes() {
        let report = |r: &str| {
            format!("rustc {r} (abc 2026-10-13)\nbinary: rustc\nrelease: {r}\nLLVM version: 21\n")
        };
        assert!(compiler_problems(&report("1.99.1"), "1.99.1").is_empty());
        assert_eq!(
            compiler_problems(&report("1.100.0-nightly"), "1.99.1").len(),
            1
        );
        assert_eq!(compiler_problems(&report("1.99.0"), "1.99.1").len(), 1);
        assert_eq!(
            compiler_problems(&report("1.99.1-beta.2"), "1.99.1-beta.2").len(),
            1
        );
        assert_eq!(compiler_problems("", "1.99.1").len(), 1);
    }

    #[test]
    fn only_an_unsafe_code_error_is_a_refusal() {
        let msg = |level: &str, code: &str| {
            format!(
                "{{\"reason\":\"compiler-message\",\"message\":{{\"level\":\"{level}\",\"code\":{{\"code\":\"{code}\"}}}}}}"
            )
        };
        assert!(refused_by_unsafe_code(&msg("error", "unsafe_code")));
        // A warning of it, beside an unrelated error, is not a refusal.
        let mixed = format!(
            "{}\n{}",
            msg("warning", "unsafe_code"),
            msg("error", "missing_docs")
        );
        assert!(!refused_by_unsafe_code(&mixed));
        assert!(!refused_by_unsafe_code("usage of an `unsafe` block"));
        assert!(!refused_by_unsafe_code(""));
    }

    #[test]
    fn the_attribute_is_found_wherever_rust_accepts_it() {
        assert!(forbids_unsafe(
            "// SPDX\n/*! crate docs */\n#![doc = \"a ] in a string\"]\n#![forbid(unsafe_code)]\n"
        ));
        assert!(forbids_unsafe(
            "#!/usr/bin/env run-cargo-script\n#![forbid(unsafe_code)]"
        ));
        assert!(forbids_unsafe("#![forbid(missing_docs, unsafe_code)]"));
        // Raw spellings, which rustc enforces the same (found in review).
        assert!(forbids_unsafe("#![forbid(r#unsafe_code)]"));
        assert!(forbids_unsafe("#![r#forbid(unsafe_code)]"));
        assert!(forbids_unsafe("#![ forbid ( unsafe_code ) ]"));
        assert!(!forbids_unsafe("#![forbid(unsafe_code_x)]"));
    }

    fn table(s: &str) -> toml::Table {
        s.parse().expect("test TOML")
    }

    #[test]
    fn lints_must_come_from_the_workspace() {
        assert!(takes_workspace_lints(&table(
            "[package]\nname = \"a\"\n\n[lints]\nworkspace = true\n"
        )));
        assert!(!takes_workspace_lints(&table(
            "[package]\nworkspace = true\n[lints]\n"
        )));
        assert!(!takes_workspace_lints(&table(
            "[lints.rust]\nunsafe_code = \"allow\"\n"
        )));
        // The words, inside a string, are not the table.
        assert!(!takes_workspace_lints(&table(
            "[package]\ndescription = \"\"\"\n[lints]\nworkspace = true\n\"\"\"\n"
        )));
    }

    #[test]
    fn the_workspace_itself_must_forbid_unsafe() {
        assert!(workspace_forbids_unsafe(&table(
            "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n"
        )));
        assert!(workspace_forbids_unsafe(&table(
            "[workspace.lints.rust]\nunsafe_code = { level = \"forbid\", priority = 0 }\n"
        )));
        assert!(!workspace_forbids_unsafe(&table(
            "[workspace.lints.rust]\nunsafe_code = \"deny\"\n"
        )));
        assert!(!workspace_forbids_unsafe(&table("[workspace]\n")));
    }
}
