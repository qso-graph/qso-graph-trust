// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! Astra's three networking bypasses, planted as source and never executed.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        let work = Self(xtask::fresh_temp_dir("qgt-network-bypasses").expect("fresh directory"));
        let names = [
            "qso-graph-trust",
            xtask::UNSAFE_BINDING,
            "middle",
            "helper",
            "qso-graph-trust-cli",
            "dev-only",
            "build-only",
        ];
        work.write(
            "Cargo.toml",
            &format!("[workspace]\nmembers = {names:?}\nresolver = \"3\"\n"),
        );
        for name in names {
            work.write(
                &format!("{name}/Cargo.toml"),
                &format!("[package]\nname = {name:?}\nversion = \"0.0.0\"\nedition = \"2024\"\n"),
            );
            work.source(name, "#![forbid(unsafe_code)]\npub fn clean() {}\n");
        }
        work.write(
            "qso-graph-trust/Cargo.toml",
            "[package]\nname = \"qso-graph-trust\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
             [dependencies]\nmiddle = { path = \"../middle\" }\n\
             qso-graph-trust-awslc = { path = \"../qso-graph-trust-awslc\" }\n\
             [dev-dependencies]\ndev-only = { path = \"../dev-only\" }\n\
             [build-dependencies]\nbuild-only = { path = \"../build-only\" }\n",
        );
        // The re-exporting helper is transitive, renamed, optional and only on
        // Windows: checking two named packages or default features misses it.
        work.write(
            "middle/Cargo.toml",
            "[package]\nname = \"middle\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
             [features]\nwire = [\"dep:wire\"]\n\
             [target.'cfg(windows)'.dependencies]\n\
             wire = { package = \"helper\", path = \"../helper\", optional = true }\n",
        );
        work.source("helper", "#![forbid(unsafe_code)]\npub struct Wire;\n");
        work.source(
            "middle",
            "#![forbid(unsafe_code)]\n#[cfg(windows)] pub use wire::Wire;\n",
        );
        // Networking belongs outside the library's normal graph. These must
        // stay outside the scan even though Cargo lists them in the workspace.
        for name in ["qso-graph-trust-cli", "dev-only", "build-only"] {
            work.source(
                name,
                "#![forbid(unsafe_code)]\npub use std::net::TcpStream as Wire;\n",
            );
        }
        let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(work.0.join("Cargo.toml"))
            .output()
            .expect("local Cargo lockfile");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        work
    }

    fn write(&self, rel: &str, text: &str) {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, text).expect("write fixture");
    }

    fn source(&self, name: &str, text: &str) {
        self.write(&format!("{name}/src/lib.rs"), text);
    }

    fn metadata(&self, target: Option<&str>) -> serde_json::Value {
        xtask::metadata_for(&self.0.join("Cargo.toml"), target).expect("fixture metadata")
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove fixture");
    }
}

#[test]
fn binding_cannot_include_unscanned_payloads() {
    let work = Workspace::new();
    let meta = work.metadata(None);
    assert!(xtask::no_network(&meta).is_empty());
    work.write(
        "qso-graph-trust-awslc/src/payload.md",
        "pub fn probe() { let _ = std::net::TcpListener::bind(\"127.0.0.1:0\"); }",
    );
    for plant in [
        "include!(concat!(\"payload\", \".md\"));",
        "const S: &str = include_str!(concat!(\"payload\", \".md\"));",
        "const B: &[u8] = include_bytes!(concat!(\"payload\", \".md\"));",
        "use core::include as load; load!(concat!(\"payload\", \".md\"));",
        "use core::include_str as load; load!(\"payload.md\");",
        "use core::include_bytes as load; load!(\"payload.md\");",
        "#[cfg(any())] mod hidden { r#include!(concat!(\"payload\", \".md\")); }",
    ] {
        work.source(xtask::UNSAFE_BINDING, plant);
        let findings = xtask::no_network(&meta);
        assert!(!findings.is_empty(), "missed {plant}");
        assert!(
            findings
                .iter()
                .all(|f| f.contains("src") && f.contains("include")),
            "{findings:?}"
        );
        work.source(xtask::UNSAFE_BINDING, "pub fn clean() {}\n");
        assert!(xtask::no_network(&meta).is_empty());
    }
}

#[test]
fn helper_reexports_are_scanned_on_every_shipping_target_with_all_features() {
    let work = Workspace::new();
    for target in xtask::SHIPPING_TARGETS {
        let meta = work.metadata(Some(target));
        assert!(xtask::no_network(&meta).is_empty(), "{target}");
        work.source(
            "helper",
            "#![forbid(unsafe_code)]\npub use std::net::TcpStream as Wire;\n",
        );
        work.source(
            "qso-graph-trust",
            "#![forbid(unsafe_code)]\n#[cfg(windows)] pub fn probe() {\n\
             let _ = middle::Wire::connect(\"127.0.0.1:9\"); }\n",
        );
        let findings = xtask::no_network(&meta);
        if target.contains("windows") {
            assert_eq!(findings.len(), 2, "{target}: {findings:?}");
            assert!(
                findings
                    .iter()
                    .all(|f| f.contains("helper") && f.contains("network")),
                "{findings:?}"
            );
        } else {
            assert!(findings.is_empty(), "{target}: {findings:?}");
        }
        work.source("helper", "#![forbid(unsafe_code)]\npub struct Wire;\n");
        assert!(xtask::no_network(&meta).is_empty(), "{target}");
    }
}

#[test]
fn binding_socket_bios_are_refused_without_running_them() {
    let work = Workspace::new();
    let meta = work.metadata(None);
    assert!(xtask::no_network(&meta).is_empty());
    work.source(
        xtask::UNSAFE_BINDING,
        "#[allow(unsafe_code)] pub fn probe() {\n\
         let bio = unsafe { aws_lc_sys::BIO_new_connect(c\"127.0.0.1:9\".as_ptr()) };\n\
         let _ = unsafe { aws_lc_sys::BIO_do_connect(bio) }; }\n",
    );
    let findings = xtask::no_network(&meta);
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(
        findings
            .iter()
            .all(|f| f.contains("BINDING_AWS_LC_ALLOWED")),
        "{findings:?}"
    );
    work.source(xtask::UNSAFE_BINDING, "pub fn clean() {}\n");
    assert!(xtask::no_network(&meta).is_empty());
}

#[test]
fn binding_provider_paths_imports_and_aliases_are_checked_as_tokens() {
    let scan = |s: &str| xtask::binding_tokens(s.parse().expect("Rust tokens"));
    for item in xtask::BINDING_AWS_LC_ALLOWED {
        for clean in [
            format!("aws_lc_sys::{item}"),
            format!("sys::r#{item}"),
            format!("use aws_lc_sys::{item} as Alias;"),
            format!("use aws_lc_sys::{{{item} as Alias}};"),
        ] {
            assert!(scan(&clean).is_empty(), "refused {clean}");
        }
    }
    for clean in [
        "use aws_lc_sys as sys;",
        "use r#aws_lc_sys as r#sys;",
        "let cbb = sys::CBB::default();",
        "use aws_lc_sys::{RSA, EVP_PKEY as Key, {BN_new, BN_free}};",
        "// aws_lc_sys::BIO_new_connect\nconst S: &str = \"sys::BIO_do_connect\";",
        "/// include! and sys::BIO_new_connect\npub fn f() {}",
    ] {
        assert!(scan(clean).is_empty(), "refused {clean}");
    }
    for plant in [
        "aws_lc_sys::BIO_new_connect(c\"127.0.0.1:9\".as_ptr())",
        "sys::BIO_do_connect(bio)",
        "r#aws_lc_sys::r#BIO_new_connect",
        "#[cfg(any())] fn f() { sys::BIO_new_socket(0, 0); }",
        "sys::BIO",
        "sys::BIO_NOCLOSE",
        "use aws_lc_sys::*;",
        "use sys::*;",
        "use aws_lc_sys::{RSA, *};",
        "use aws_lc_sys::{RSA, BIO_new_connect as connect};",
        "use aws_lc_sys as other; other::BIO_new_connect();",
        "extern crate aws_lc_sys as other;",
        "use sys as other;",
        "use aws_lc_sys::{self as other};",
        "pub use aws_lc_sys;",
        "consume!(sys::BIO_new_connect)",
    ] {
        assert!(!scan(plant).is_empty(), "missed {plant}");
    }
}

#[test]
fn cargo_cannot_rename_the_provider_outside_the_checked_names() {
    let work = Workspace::new();
    let mut meta = work.metadata(None);
    let binding = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .position(|p| p["name"] == xtask::UNSAFE_BINDING)
        .expect("binding");
    for alias in [
        serde_json::Value::Null,
        "aws_lc_sys".into(),
        "sys".into(),
        "hidden".into(),
    ] {
        // Mutate Cargo's dependency description without resolving or executing
        // an outside crate. Renaming it must not evade the token allowlist.
        meta["packages"][binding]["dependencies"] = serde_json::json!([
            {"name": "aws-lc-sys", "rename": alias}
        ]);
        let findings = xtask::no_network(&meta);
        if alias == "hidden" {
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert!(findings[0].contains("renames aws-lc-sys to hidden"));
        } else {
            assert!(findings.is_empty(), "{alias}: {findings:?}");
        }
    }
    meta["packages"][binding]["dependencies"] = serde_json::json!([]);
    assert!(xtask::no_network(&meta).is_empty());
}
