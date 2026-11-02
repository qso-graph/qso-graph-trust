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
                for word in ["cap-lints", "force-warn", "unsafe_code"] {
                    if text.contains(word) {
                        problems.push(format!("workflow {name} mentions {word}"));
                    }
                }
            }
        }
    }
    for (var, value) in std::env::vars() {
        let flags = var == "RUSTFLAGS"
            || var == "CARGO_ENCODED_RUSTFLAGS"
            || var == "CARGO_BUILD_RUSTFLAGS"
            || (var.starts_with("CARGO_TARGET_") && var.ends_with("_RUSTFLAGS"));
        if flags && flags_weaken_unsafe(&value) {
            problems.push(format!("{var} weakens lints: {value}"));
        }
    }
    problems.sort();
    problems
}

/// Whether compiler flags cap lints or lower `unsafe_code` below forbid.
pub fn flags_weaken_unsafe(flags: &str) -> bool {
    let words: Vec<&str> = flags
        .split(|c: char| c.is_whitespace() || c == '\u{1f}')
        .filter(|w| !w.is_empty())
        .collect();
    words.iter().enumerate().any(|(i, w)| {
        let next = words.get(i + 1).copied().unwrap_or("");
        w.starts_with("--cap-lints")
            || w.starts_with("--force-warn")
            || matches!(*w, "-A" | "-W" | "--allow" | "--warn") && next == "unsafe_code"
            || matches!(
                *w,
                "-Aunsafe_code" | "-Wunsafe_code" | "--allow=unsafe_code" | "--warn=unsafe_code"
            )
    })
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
    fn flags_that_cap_or_lower_the_lint_are_refused() {
        for f in [
            "--cap-lints=allow",
            "-D warnings --cap-lints warn",
            "-A unsafe_code",
            "-Aunsafe_code",
            "--allow=unsafe_code",
            "-W unsafe_code",
            "--force-warn unsafe_code",
            "-D warnings\u{1f}--cap-lints=allow",
        ] {
            assert!(flags_weaken_unsafe(f), "{f}");
        }
        for f in [
            "",
            "-D warnings",
            "-C target-cpu=native",
            "-A dead_code",
            "-D unsafe_code",
        ] {
            assert!(!flags_weaken_unsafe(f), "{f}");
        }
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
