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
//!
//! Each check is proved by planted cases it must catch (tests/planted.rs), and
//! anything a check cannot read counts as a failure, never a pass.

#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::process::Command;

/// The crates that hold the key, the signing and the file parsers.
pub const PROTECTED: &[&str] = &["qso-graph-trust"];

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

/// Native links allowed in the protected tree, each by exact crate name with its
/// reason. None today; any added here is a decision recorded in docs/decisions,
/// never a pattern or a prefix.
const EXEMPT: &[(&str, &str)] = &[];

/// Crates from outside the workspace allowed in the protected tree, each by exact
/// name and version from crates.io (where a published version can never change),
/// read and found to bring no native code: no `#[link]` or `extern` block, no
/// assembly, and a build script or procedural macro, if it has one, that compiles
/// nothing. A new version is a new entry, because it is new code (found by Codex
/// review: a build script can run a compiler, and an `extern` block can link a
/// library, without declaring `links`).
const REVIEWED: &[(&str, &str, &str)] = &[];

/// The one registry a reviewed crate may come from.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Rust that links native code or holds assembly, as it reads with whitespace
/// removed. A match in a comment fails too: the check fails closed, and the crate
/// is then read and exempted by name.
const NATIVE_RUST: &[(&str, &str)] = &[
    ("#[link(", "has a #[link] attribute"),
    ("#[link_name", "has a #[link_name] attribute"),
    ("#[link_section", "has a #[link_section] attribute"),
    ("unsafeextern", "declares foreign functions"),
    ("extern\"C\"{", "declares foreign functions"),
    ("extern\"system\"{", "declares foreign functions"),
    ("asm!(", "holds inline assembly"),
    ("global_asm!(", "holds assembly"),
    ("naked_asm!(", "holds assembly"),
];

/// Native source, assembly and object code, by file extension.
const NATIVE_FILES: &[&str] = &[
    "a", "asm", "c", "cc", "cpp", "cxx", "dll", "dylib", "h", "hpp", "lib", "o", "obj", "s", "so",
];

/// `cargo metadata` for every platform and every feature, of the workspace at
/// `manifest`, from its committed lockfile: a native dependency behind a feature
/// nobody enables by default is still one a user can switch on (found by Codex
/// review).
pub fn metadata(manifest: &Path) -> Result<Value, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
            "--manifest-path",
        ])
        .arg(manifest)
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

fn exempt(name: &str) -> bool {
    EXEMPT.iter().any(|(n, _)| *n == name)
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
    no_c_reviewing(meta, protected, REVIEWED)
}

/// [`no_c`] with the reviewed list given, so tests can name their own.
fn no_c_reviewing(meta: &Value, protected: &[&str], list: &[(&str, &str, &str)]) -> Vec<String> {
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
        // (found by Codex review).
        if found.is_empty() {
            problems.push(format!("protected crate {want} is not in this workspace"));
        }
        for id in &found {
            if !workspace.contains(id) {
                problems.push(format!("protected crate {want} is not a workspace member"));
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
            && !exempt(&name)
        {
            problems.push(format!("{name} links the native library {links}"));
        }
        if !workspace.contains(id) {
            if pkg.and_then(|p| p["source"].as_str()) != Some(CRATES_IO) {
                problems.push(format!("{name} {version} is not a crates.io crate"));
            }
            if !reviewed(&name, &version) {
                problems.push(format!("{name} {version} has not been reviewed"));
            }
        }
        if let Some(dir) = pkg
            .and_then(|p| p["manifest_path"].as_str())
            .and_then(|m| Path::new(m).parent())
        {
            // A target's source outside its crate's directory would be outside the
            // search below (found by Codex review).
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
            if !exempt(&name) {
                for found in native_in(dir) {
                    problems.push(format!("{name} {version}: {found}"));
                }
            }
        }
        for target in pkg.and_then(|p| p["targets"].as_array()).unwrap_or(&empty) {
            let kinds = target["kind"].as_array().unwrap_or(&empty);
            for (kind, what) in [
                ("custom-build", "a build script"),
                ("proc-macro", "a procedural macro"),
            ] {
                if kinds.iter().any(|k| k == kind) && !reviewed(&name, &version) {
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
            let dep_name = field(dep_id, "name");
            if NATIVE_BUILD.contains(&dep_name.as_str()) && !exempt(&name) {
                problems.push(format!("{name} builds native code through {dep_name}"));
            }
            queue.push_back(dep_id);
        }
    }
    problems.sort();
    problems.dedup();
    problems
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
fn native_in(dir: &Path) -> Vec<String> {
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
                if !matches!(rel.as_str(), "target" | ".git") {
                    stack.push(path);
                }
                continue;
            }
            let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());
            if let Some(ext) = &ext
                && NATIVE_FILES.contains(&ext.as_str())
            {
                found.push(format!("{rel} is native code"));
            } else if ext.as_deref() == Some("rs") {
                let compact: String = std::fs::read_to_string(&path)
                    .unwrap_or_else(|_| "unreadable".to_string())
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                if compact == "unreadable" {
                    found.push(format!("{rel} cannot be read"));
                }
                for (pattern, what) in NATIVE_RUST {
                    if compact.contains(pattern) {
                        found.push(format!("{rel} {what}"));
                    }
                }
            }
        }
    }
    found
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
    for pkg in meta["packages"].as_array().unwrap_or(&empty) {
        if !pkg["id"].as_str().is_some_and(|id| workspace.contains(id)) {
            continue;
        }
        let pkg_name = pkg["name"].as_str().unwrap_or("?");
        // Edition 2024 makes an `extern` block without `unsafe` a hard error, so with
        // unsafe code forbidden the compiler refuses every foreign block, all
        // assembly and `no_mangle` in a workspace crate. Edition 2021 accepts
        // `extern "C" {}` without `unsafe` even under forbid (found by Codex review,
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
        match pkg["manifest_path"]
            .as_str()
            .map(|m| read_toml(Path::new(m)))
        {
            Some(Ok(t)) if takes_workspace_lints(&t) => {}
            Some(Ok(_)) => problems.push(format!("{pkg_name} does not take the workspace's lints")),
            Some(Err(e)) => problems.push(e),
            None => problems.push(format!("{pkg_name} has no manifest path")),
        }
        for target in pkg["targets"].as_array().unwrap_or(&empty) {
            let Some(src) = target["src_path"].as_str() else {
                continue;
            };
            match std::fs::read_to_string(src) {
                Ok(text) if forbids_unsafe(&text) => {}
                Ok(_) => problems.push(format!("{src} does not say #![forbid(unsafe_code)]")),
                Err(e) => problems.push(format!("cannot read {src}: {e}")),
            }
        }
    }
    problems.sort();
    problems
}

fn read_toml(path: &Path) -> Result<toml::Table, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    text.parse::<toml::Table>()
        .map_err(|e| format!("{} is not valid TOML: {e}", path.display()))
}

/// Whether a member's manifest says `[lints] workspace = true` and nothing else
/// under `[lints]`, read as TOML, so text inside a string never counts (found by
/// Codex review).
pub fn takes_workspace_lints(manifest: &toml::Table) -> bool {
    manifest
        .get("lints")
        .and_then(toml::Value::as_table)
        .is_some_and(|l| l.len() == 1 && l.get("workspace") == Some(&toml::Value::Boolean(true)))
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

/// Every way a build of this repository could have its lints weakened, sorted.
/// `--cap-lints` overrides even `forbid(unsafe_code)` (found by Codex review, and
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
            // An alias can pass any flag (found by Codex review), so the one alias is
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
    // and no `rustflags` in any profile (found by Codex review).
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
            let in_cargo_dir = d.file_name().is_some_and(|n| n == ".cargo");
            if in_cargo_dir && matches!(name.as_str(), "config" | "config.toml") && path != config {
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
                // it would not reach this check's own environment.
                for line in text.lines().filter(|l| l.contains("RUSTFLAGS")) {
                    if line.trim() != "RUSTFLAGS: -D warnings" {
                        problems.push(format!("workflow {name} sets RUSTFLAGS: {}", line.trim()));
                    }
                }
            }
        }
    }
    problems.extend(env_problems(std::env::vars()));
    problems.sort();
    problems
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

/// The one alias the repository's Cargo configuration may hold.
pub const XTASK_ALIAS: &str = "run --quiet --locked --package xtask --";

/// Words no workflow may contain: each is a way to hand the compiler flags,
/// another configuration, another compiler or a linker argument that this
/// check would not see (found by Codex review). Failing on the word, even in a
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
/// different compiler, wrapper or linker (found by Codex review: wrappers and
/// response files reach rustc without passing through RUSTFLAGS's words).
pub fn env_problems(vars: impl IntoIterator<Item = (String, String)>) -> Vec<String> {
    let mut problems = Vec::new();
    for (var, value) in vars {
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
/// flags so far had a way around it (found by Codex review).
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

/// The canary: build the real library, in a copy of this repository (its
/// manifests and profiles, its Cargo configuration, its toolchain file) with an
/// `unsafe` block added, in this build's real environment (its flags and any
/// wrapper), and require the compiler to refuse it with an `unsafe_code` error.
/// The other checks look for known ways to weaken the lints; this one measures
/// the result on the crate that matters, so a way nobody listed still fails it.
/// It reads the compiler's JSON diagnostics: an `unsafe_code` warning beside an
/// unrelated error is not a refusal (found by Codex review, as were the profile
/// flags a stand-in crate could not see). `extra_env` is for the planted test.
pub fn canary(root: &Path, target_dir: &Path, extra_env: &[(&str, &str)]) -> Result<(), String> {
    // Absolute, because the child Cargo runs from the copy, not from where this
    // was called (found by Codex review).
    let target_dir = std::path::absolute(target_dir)
        .map_err(|e| format!("cannot resolve {}: {e}", target_dir.display()))?;
    let copy = target_dir.join("qgt-canary");
    if copy.exists() {
        std::fs::remove_dir_all(&copy)
            .map_err(|e| format!("cannot clear {}: {e}", copy.display()))?;
    }
    copy_repository(root, &copy, &target_dir)?;
    let lib = copy
        .join("crates")
        .join("qso-graph-trust")
        .join("src")
        .join("lib.rs");
    let mut source =
        std::fs::read_to_string(&lib).map_err(|e| format!("cannot read {}: {e}", lib.display()))?;
    source.push_str("\n/// The canary's probe: the compiler must refuse it.\npub fn qgt_canary() -> u8 {\n    unsafe { core::ptr::read(&7) }\n}\n");
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
        .arg(copy.join("target"))
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
/// `error`: a warning of it beside some other error is not a refusal (found by
/// Codex review).
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
fn copy_repository(from: &Path, to: &Path, output: &Path) -> Result<(), String> {
    let output = std::fs::canonicalize(output).ok();
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
                if name == ".git" || name == "target" || is_output {
                    continue;
                }
                stack.push((path, dst.join(name)));
            } else if kind.is_file() {
                std::fs::copy(&path, dst.join(&name))
                    .map_err(|e| format!("cannot copy {}: {e}", path.display()))?;
            }
        }
    }
    Ok(())
}

/// Whether a crate root forbids unsafe code with an inner attribute that the
/// compiler applies: `#![forbid(...)]` naming the lint `unsafe_code`, not under
/// `cfg_attr`. The file is parsed by `syn`, a complete Rust parser, so shebangs,
/// comments, raw strings, raw identifiers and raw lifetimes are read as Rust reads
/// them; text inside any of them is never taken for the attribute. A hand-written
/// lexer was tried first and each of four Codex review rounds found a construct it
/// misread, so it was replaced. A file `syn` cannot parse counts as absent: the
/// check fails closed.
pub fn forbids_unsafe(source: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    file.attrs.iter().any(|a| {
        if !matches!(a.style, syn::AttrStyle::Inner(_)) || !a.path().is_ident("forbid") {
            return false;
        }
        // `forbid(...)` only: rustc rejects `forbid[...]` and `forbid{...}` (found by
        // Codex review), so neither may count.
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
            } else if meta.path.is_ident("unsafe_code")
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
        // Unreviewed, a crate with a build script fails twice: as an outside crate and for the script.
        let mut g = graph(json!("dev"));
        g["packages"][1]["targets"] = json!([{"kind": ["lib"]}, {"kind": ["custom-build"]}]);
        assert_eq!(
            no_c(&g, PROTECTED),
            vec![
                "middle 1.0.0 has a build script that has not been reviewed",
                "middle 1.0.0 has not been reviewed",
            ]
        );
        g["packages"][1]["targets"] = json!([{"kind": ["proc-macro"]}]);
        assert_eq!(
            no_c(&g, PROTECTED),
            vec![
                "middle 1.0.0 has a procedural macro that has not been reviewed",
                "middle 1.0.0 has not been reviewed",
            ]
        );
        // Reviewed, it passes: the review covers the script.
        assert!(check(&g, PROTECTED).is_empty());
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

    /// The test graph's outside crates, reviewed, so each test sees only its own finding.
    const TEST_REVIEWED: &[(&str, &str, &str)] =
        &[("middle", "1.0.0", "test"), ("cc", "1.2.0", "test")];

    fn check(g: &Value, protected: &[&str]) -> Vec<String> {
        no_c_reviewing(g, protected, TEST_REVIEWED)
    }

    #[test]
    fn an_outside_crate_must_be_from_crates_io_and_reviewed() {
        let mut g = graph(json!("dev"));
        assert_eq!(
            no_c(&g, PROTECTED),
            vec!["middle 1.0.0 has not been reviewed"]
        );
        g["packages"][1]["source"] = json!("git+https://example.invalid/middle");
        assert_eq!(
            check(&g, PROTECTED),
            vec!["middle 1.0.0 is not a crates.io crate"]
        );
        // A reviewed name at another version is new code, so not reviewed.
        g["packages"][1]["source"] = json!(CRATES_IO);
        g["packages"][1]["version"] = json!("1.0.1");
        assert_eq!(
            check(&g, PROTECTED),
            vec!["middle 1.0.1 has not been reviewed"]
        );
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
        // A raw string whose text looks like an attribute (Codex review, round 2).
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
        // `r#r` is a raw identifier; the string after it is ordinary (Codex review, round 4).
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
        // `'r#r` is a raw lifetime; the string after it is ordinary (Codex review, round 5).
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
