// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! The repository's policy checks, run by `cargo xtask policy` and by CI.
//!
//! - **No C in the library** (docs/decisions/0002-no-c-in-the-library.md): nothing
//!   in the dependency tree of [`PROTECTED`] links a native library or builds
//!   C, C++ or assembly, on any platform.
//! - **No unsafe code** (AGENTS.md): every crate root in the workspace says
//!   `#![forbid(unsafe_code)]` and every crate takes the workspace's lints.
//!
//! Each check is proved by a planted case it must catch (tests/planted.rs).

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

/// Exemptions, each by exact crate name with its reason. None today; any added
/// here is a decision recorded in docs/decisions, never a pattern or a prefix.
const EXEMPT: &[(&str, &str)] = &[];

/// `cargo metadata` for every platform, of the workspace at `manifest`.
pub fn metadata(manifest: &Path) -> Result<Value, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--manifest-path"])
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

/// Every package the protected crates need to build and run (normal and build
/// dependencies; never dev-dependencies, which only the tests use), and each
/// reason one of them brings native code. Empty means the check passes.
pub fn no_c(meta: &Value, protected: &[&str]) -> Vec<String> {
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
    let name = |id: &str| {
        packages
            .get(id)
            .and_then(|p| p["name"].as_str())
            .unwrap_or(id)
            .to_string()
    };

    let mut problems = Vec::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for want in protected {
        let found: Vec<&str> = packages
            .iter()
            .filter(|(_, p)| p["name"].as_str() == Some(want) && p["source"].is_null())
            .map(|(id, _)| *id)
            .collect();
        if found.is_empty() {
            // A renamed or missing crate must fail, or the check passes by checking nothing.
            problems.push(format!("protected crate {want} is not in this workspace"));
        }
        queue.extend(found);
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let pkg_name = name(id);
        if let Some(links) = packages.get(id).and_then(|p| p["links"].as_str())
            && !exempt(&pkg_name)
        {
            problems.push(format!("{pkg_name} links the native library {links}"));
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
            let dep_name = name(dep_id);
            if NATIVE_BUILD.contains(&dep_name.as_str()) && !exempt(&pkg_name) {
                problems.push(format!("{pkg_name} builds native code through {dep_name}"));
            }
            queue.push_back(dep_id);
        }
    }
    problems
}

/// Every crate root of every workspace member that does not forbid unsafe code,
/// and every member that does not take the workspace's lints.
pub fn no_unsafe(meta: &Value) -> Vec<String> {
    let empty = Vec::new();
    let members: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut problems = Vec::new();
    if members.is_empty() {
        problems.push("the workspace has no members".to_string());
    }
    for pkg in meta["packages"].as_array().unwrap_or(&empty) {
        if !pkg["id"].as_str().is_some_and(|id| members.contains(id)) {
            continue;
        }
        let pkg_name = pkg["name"].as_str().unwrap_or("?");
        if let Some(manifest) = pkg["manifest_path"].as_str() {
            match std::fs::read_to_string(manifest) {
                Ok(text) if takes_workspace_lints(&text) => {}
                Ok(_) => problems.push(format!("{pkg_name} does not take the workspace's lints")),
                Err(e) => problems.push(format!("{pkg_name}: cannot read {manifest}: {e}")),
            }
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
    problems
}

/// Whether a crate root carries the attribute on a line of its own, not in a comment.
pub fn forbids_unsafe(source: &str) -> bool {
    source
        .lines()
        .any(|l| l.trim() == "#![forbid(unsafe_code)]")
}

/// Whether a manifest has `[lints]` with `workspace = true` under it.
pub fn takes_workspace_lints(manifest: &str) -> bool {
    let mut in_lints = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_lints = line == "[lints]";
        } else if in_lints && line.replace(' ', "") == "workspace=true" {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph(cc_kind: Value) -> Value {
        json!({
            "packages": [
                {"id": "lib", "name": "qso-graph-trust", "source": null, "links": null},
                {"id": "mid", "name": "middle", "source": "registry", "links": null},
                {"id": "cc", "name": "cc", "source": "registry", "links": null}
            ],
            "resolve": {"nodes": [
                {"id": "lib", "deps": [{"pkg": "mid", "dep_kinds": [{"kind": null}]}]},
                {"id": "mid", "deps": [{"pkg": "cc", "dep_kinds": [{"kind": cc_kind}]}]},
                {"id": "cc", "deps": []}
            ]}
        })
    }

    #[test]
    fn a_build_script_compiling_c_two_levels_down_is_caught() {
        let problems = no_c(&graph(json!("build")), PROTECTED);
        assert_eq!(problems, vec!["middle builds native code through cc"]);
    }

    #[test]
    fn a_dev_dependency_is_not_shipped_so_not_caught() {
        assert!(no_c(&graph(json!("dev")), PROTECTED).is_empty());
    }

    #[test]
    fn a_missing_protected_crate_fails_rather_than_checking_nothing() {
        let problems = no_c(&graph(json!("build")), &["renamed"]);
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
    fn lints_must_come_from_the_workspace() {
        assert!(takes_workspace_lints(
            "[package]\nname = \"a\"\n\n[lints]\nworkspace = true\n"
        ));
        assert!(!takes_workspace_lints(
            "[package]\nworkspace = true\n[lints]\n"
        ));
        assert!(!takes_workspace_lints(
            "[lints.rust]\nunsafe_code = \"allow\"\n"
        ));
    }
}
