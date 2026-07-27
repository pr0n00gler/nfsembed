use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn repository_file(relative: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    fs::read_to_string(repository_file(relative)).unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn command_tokens(command: &str) -> impl Iterator<Item = &str> {
    command.split(|character: char| character.is_whitespace() || matches!(character, ';' | '&' | '|' | '(' | ')'))
}

#[test]
fn make_recipes_do_not_invoke_host_scripting_runtimes() {
    let banned = ["python", "python3", "node", "npm", "npx", "bun", "deno", "ts-node"];

    fn visit(directory: &Path, banned: &[&str]) {
        for entry in
            fs::read_dir(directory).unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        {
            let entry = entry.expect("failed to read directory entry");
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|name| name.to_str());
                if !matches!(name, Some(".git" | "target")) {
                    visit(&path, banned);
                }
                continue;
            }
            let is_makefile = path.file_name().and_then(|name| name.to_str()) == Some("Makefile")
                || path.extension().and_then(|extension| extension.to_str()) == Some("mk");
            if !is_makefile {
                continue;
            }
            let contents =
                fs::read_to_string(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            for (line_number, line) in contents.lines().enumerate() {
                let Some(recipe) = line.strip_prefix('\t') else {
                    continue;
                };
                for runtime in banned {
                    assert!(
                        !command_tokens(recipe).any(|token| token == *runtime),
                        "{}:{} invokes host runtime {runtime}: {recipe}",
                        path.display(),
                        line_number + 1
                    );
                }
            }
        }
    }

    visit(Path::new(env!("CARGO_MANIFEST_DIR")), &banned);
}

#[test]
fn contributor_docs_do_not_show_host_scripting_runtime_commands() {
    let banned = [
        "python", "python3", "pip", "pip3", "node", "npm", "npx", "bun", "deno", "ts-node",
    ];
    for document in [
        "README.md",
        "CONTRIBUTING.md",
        "fuzz/README.md",
        "tests/README.md",
        "tests/native/README.md",
    ] {
        let contents = read(document);
        for (line_number, line) in contents.lines().enumerate() {
            let command = line.trim_start().strip_prefix("$ ").unwrap_or(line.trim_start());
            let first = command.split_whitespace().next();
            assert!(
                !first.is_some_and(|token| banned.contains(&token)),
                "{document}:{} instructs a host scripting runtime command: {line}",
                line_number + 1
            );
        }
    }
}

#[test]
fn compose_exposes_the_required_profiled_tooling_services() {
    let compose = read("compose.yaml");
    for service in ["tools", "script-runner", "pynfs", "kdc"] {
        assert!(compose.contains(&format!("\n  {service}:\n")), "compose.yaml is missing the {service} service");
    }
    assert!(!compose.contains(":latest"));
    assert!(compose.contains("profiles:\n      - interop"));
    assert!(compose.contains("profiles:\n      - kerberos"));
    assert!(!compose.contains("88:88"), "the test KDC must not publish host ports");
}

#[test]
fn real_kdc_gate_is_container_wired_and_cannot_silently_skip() {
    let compose = read("compose.yaml");
    let kdc = read("tests/docker/kdc.Dockerfile");
    let kdc_config = read("tests/docker/kerberos/kdc.conf");
    let kdc_entrypoint = read("tests/docker/kdc-entrypoint.sh");
    let makefile = read("Makefile");

    assert!(compose.contains("SSPI_KDC_URL: tcp://kdc:88"));
    assert!(compose.contains("NFSEMBED_GSS_CLIENT_KEYTAB: /run/nfsembed-kdc/client.keytab"));
    assert!(compose.contains("NFSEMBED_GSS_SERVER_KEYTAB: /run/nfsembed-kdc/nfs.keytab"));
    assert!(compose.contains("kdc-keytabs:/run/nfsembed-kdc:ro"));
    assert!(!compose.contains("KRB5_MASTER_PASSWORD"));
    assert!(kdc.contains("heimdal-kdc"));
    assert!(kdc_config.contains("encode_as_rep_as_tgs_rep = false"));
    assert!(kdc_entrypoint.contains("/usr/lib/heimdal-servers/kdc"));
    assert!(makefile.contains("test-gss: kdc-up"));
    assert!(makefile.contains("cargo test --locked --test gss_kdc -- --ignored --exact"));
    assert!(makefile.contains("portable_sspi_round_trips_against_real_kdc_for_rpcsec_gss_v1_and_v2"));
    assert!(makefile.contains("trap cleanup EXIT"));
    assert!(makefile.contains("cleanup() { $(COMPOSE) --profile kerberos stop kdc; }"));
}

#[test]
fn third_party_tooling_inputs_are_immutable() {
    let compose = read("compose.yaml");
    let tools = read("tests/docker/tools.Dockerfile");
    let pynfs = read("tests/docker/pynfs.Dockerfile");
    let kdc = read("tests/docker/kdc.Dockerfile");
    let pinned_pynfs = "cd4701827a8261fedbfb4c6e39029fb9671321a6";

    assert!(compose.contains("python:3.13.5-alpine3.22@sha256:"));
    assert!(tools.contains("rust:1.96.1-bookworm@sha256:"));
    assert!(tools.contains("CARGO_FUZZ_VERSION=0.13.2"));
    assert!(tools.contains("NIGHTLY_TOOLCHAIN=nightly-2026-07-01"));
    assert!(tools.contains("--component rustfmt"));
    assert!(pynfs.contains("debian:12.11-slim@sha256:"));
    assert!(pynfs.contains(pinned_pynfs));
    assert!(kdc.contains("debian:12.11-slim@sha256:"));
}

#[test]
fn native_python_probe_is_container_routed_outside_ci() {
    let client = read("tests/native/client.sh");
    let wrapper = read("tests/run_python_entrypoint.sh");
    let windows = read("tests/native/run_windows.ps1");

    assert!(!client.contains("python3 "));
    assert!(client.contains("tests/run_python_entrypoint.sh"));
    assert!(wrapper.contains("docker compose"));
    assert!(wrapper.contains("${CI:-}"));
    assert!(windows.contains("$env:CI"));
    assert!(windows.contains("script-runner"));
}

#[cfg(unix)]
#[test]
fn scripting_language_sources_are_not_host_executables() {
    fn visit(directory: &Path, executable_sources: &mut Vec<PathBuf>) {
        for entry in
            fs::read_dir(directory).unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        {
            let entry = entry.expect("failed to read directory entry");
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|name| name.to_str());
                if !matches!(name, Some(".git" | "target")) {
                    visit(&path, executable_sources);
                }
                continue;
            }
            let extension = path.extension().and_then(|extension| extension.to_str());
            if matches!(extension, Some("py" | "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs")) {
                let mode = entry.metadata().expect("failed to read script metadata").permissions().mode();
                if mode & 0o111 != 0 {
                    executable_sources.push(path);
                }
            }
        }
    }

    let mut executable_sources = Vec::new();
    visit(Path::new(env!("CARGO_MANIFEST_DIR")), &mut executable_sources);
    assert!(
        executable_sources.is_empty(),
        "scripting-language sources must use container entrypoints, not executable bits: {executable_sources:?}"
    );
}
