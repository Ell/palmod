use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use palmod_profile::{BuildProfile, ElfFingerprint, ProfileStatus, fingerprint_path};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Fingerprint a native `PalServer` ELF.
    Fingerprint(FingerprintArgs),
    /// Seed a candidate profile and optionally run the headless Ghidra extractor.
    Analyze(AnalyzeArgs),
    /// Attach a passive Frida probe and capture its NDJSON evidence.
    Probe(ProbeArgs),
    /// Verify static + runtime evidence and promote a candidate to validated.
    Approve(ApproveArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Json,
    Toml,
}

#[derive(Debug, Args)]
struct FingerprintArgs {
    /// PalServer-Linux-Shipping ELF.
    binary: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct AnalyzeArgs {
    /// PalServer-Linux-Shipping ELF.
    binary: PathBuf,
    #[arg(long)]
    steam_build_id: String,
    #[arg(long)]
    depot_manifest: Option<String>,
    #[arg(long)]
    palworld_version: Option<String>,
    #[arg(long, default_value = "candidate.toml")]
    output: PathBuf,
    /// Pinned, memory-gated Ghidra/PyGhidra wrapper.
    #[arg(
        long,
        env = "PALMOD_GHIDRA_RUNNER",
        default_value = "reverse/bin/ghidra_scan.sh"
    )]
    ghidra_runner: PathBuf,
    /// Static evidence path; defaults beside the candidate profile.
    #[arg(long)]
    evidence: Option<PathBuf>,
    /// Additional reflected names. The wrapper supplies a useful default set.
    #[arg(long = "reflected-name")]
    reflected_names: Vec<String>,
    /// Seed only. Useful on hosts that intentionally do not have Ghidra installed.
    #[arg(long)]
    skip_ghidra: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProbeHook {
    ExecThunk,
    Implementation,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[arg(long)]
    pid: u32,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long, default_value = "reverse/frida/probe.py")]
    probe_runner: PathBuf,
    #[arg(long, default_value = "probe-evidence.ndjson")]
    evidence: PathBuf,
    #[arg(long, env = "PALMOD_PYTHON", default_value = "python3")]
    python: PathBuf,
    #[arg(long, value_enum)]
    hook: Vec<ProbeHook>,
    #[arg(long)]
    allow_candidate_profile: bool,
    #[arg(long, default_value_t = 100)]
    max_events: u32,
    #[arg(long, default_value_t = 8)]
    backtrace_depth: u8,
    #[arg(long, default_value_t = 30)]
    duration_seconds: u64,
}

#[derive(Debug, Args)]
struct ApproveArgs {
    #[arg(long)]
    candidate: PathBuf,
    /// Exact ELF against which all static anchors are checked.
    #[arg(long)]
    binary: PathBuf,
    /// NDJSON emitted by a fingerprint-gated passive `palrev probe` run.
    #[arg(long)]
    runtime_evidence: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Fingerprint(args) => fingerprint(&args),
        Commands::Analyze(args) => analyze(args),
        Commands::Probe(args) => probe(args),
        Commands::Approve(args) => approve(&args),
    }
}

fn fingerprint(args: &FingerprintArgs) -> Result<()> {
    let fingerprint = fingerprint_path(&args.binary)
        .with_context(|| format!("fingerprinting {}", args.binary.display()))?;
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&fingerprint)?),
        OutputFormat::Toml => print!("{}", toml_fingerprint(&fingerprint)?),
    }
    Ok(())
}

fn analyze(args: AnalyzeArgs) -> Result<()> {
    let binary = absolute_existing(&args.binary)?;
    let output = absolute_output(&args.output)?;
    let mut profile = BuildProfile::candidate(
        args.steam_build_id,
        fingerprint_path(&binary)
            .with_context(|| format!("fingerprinting {}", binary.display()))?,
    );
    profile.depot_manifest = args.depot_manifest;
    profile.palworld_version = args.palworld_version;
    atomic_write(&output, profile.to_toml_pretty()?.as_bytes())?;

    if args.skip_ghidra {
        eprintln!("seeded {}; Ghidra explicitly skipped", output.display());
        return Ok(());
    }

    ensure_file(&args.ghidra_runner, "Ghidra runner")?;
    let evidence = args
        .evidence
        .unwrap_or_else(|| output.with_extension("static.json"));
    let evidence = absolute_output(&evidence)?;
    let command_args = ghidra_scan_args(&binary, &evidence, &args.reflected_names);
    let status = Command::new(&args.ghidra_runner)
        .args(&command_args)
        .status()
        .with_context(|| format!("starting {}", args.ghidra_runner.display()))?;
    ensure!(status.success(), "Ghidra analysis failed with {status}");
    ensure!(
        evidence.is_file(),
        "Ghidra runner succeeded without producing {}",
        evidence.display()
    );
    eprintln!(
        "candidate profile written to {}; static evidence written to {}",
        output.display(),
        evidence.display()
    );
    Ok(())
}

fn probe(args: ProbeArgs) -> Result<()> {
    ensure_file(&args.profile, "candidate profile")?;
    ensure_file(&args.probe_runner, "Frida probe runner")?;
    let profile = BuildProfile::read_toml(&args.profile).context("validating profile")?;
    if profile.status == ProfileStatus::Candidate {
        ensure!(
            args.allow_candidate_profile,
            "candidate profile requires --allow-candidate-profile for passive research"
        );
    }
    if let Some(parent) = args.evidence.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let evidence = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&args.evidence)
        .with_context(|| format!("creating private evidence file {}", args.evidence.display()))?;
    let mut command = Command::new(&args.python);
    command
        .arg(&args.probe_runner)
        .arg("--pid")
        .arg(args.pid.to_string())
        .arg("--profile")
        .arg(absolute_existing(&args.profile)?)
        .arg("--max-events")
        .arg(args.max_events.to_string())
        .arg("--backtrace-depth")
        .arg(args.backtrace_depth.to_string())
        .arg("--duration")
        .arg(args.duration_seconds.to_string());
    if args.allow_candidate_profile {
        command.arg("--allow-candidate-profile");
    }
    for hook in args.hook {
        command.arg("--hook").arg(match hook {
            ProbeHook::ExecThunk => "exec-thunk",
            ProbeHook::Implementation => "implementation",
        });
    }
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(evidence))
        .status()
        .with_context(|| format!("starting {}", args.probe_runner.display()))?;
    ensure!(status.success(), "Frida probe failed with {status}");
    eprintln!("probe evidence written to {}", args.evidence.display());
    Ok(())
}

fn approve(args: &ApproveArgs) -> Result<()> {
    ensure_file(&args.candidate, "candidate profile")?;
    ensure_file(&args.binary, "PalServer ELF")?;
    ensure_file(&args.runtime_evidence, "runtime evidence")?;

    let mut profile = BuildProfile::read_toml(&args.candidate)?;
    ensure!(
        profile.status == ProfileStatus::Candidate,
        "profile is not a candidate"
    );
    ensure!(
        !profile.anchors.is_empty(),
        "candidate has no reviewed anchors"
    );
    let actual = fingerprint_path(&args.binary)?;
    ensure!(
        profile.matches_fingerprint(&actual),
        "candidate fingerprint does not match {}",
        args.binary.display()
    );
    profile
        .verify_anchor_bytes(&args.binary)
        .context("static anchor verification failed")?;
    validate_runtime_evidence(&args.runtime_evidence, &profile)?;

    // Promotion is just marking the profile validated; the runtime enforces the
    // fingerprint + live anchor bytes at launch. No signing.
    profile.status = ProfileStatus::Validated;
    atomic_write(&args.output, profile.to_toml_pretty()?.as_bytes())?;
    eprintln!("approved (validated) {}", args.output.display());
    Ok(())
}

fn ghidra_scan_args(binary: &Path, evidence: &Path, reflected_names: &[String]) -> Vec<OsString> {
    let mut args = vec![
        binary.as_os_str().to_owned(),
        evidence.as_os_str().to_owned(),
    ];
    args.extend(reflected_names.iter().map(OsString::from));
    args
}

fn absolute_existing(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("resolving {}", path.display()))
}

fn absolute_output(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn ensure_file(path: &Path, description: &str) -> Result<()> {
    ensure!(
        path.is_file(),
        "{description} does not exist: {}",
        path.display()
    );
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary file in {}", parent.display()))?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("persisting {}", path.display()))?;
    Ok(())
}

fn toml_fingerprint(fingerprint: &ElfFingerprint) -> Result<String> {
    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        elf: &'a ElfFingerprint,
    }
    Ok(toml::to_string_pretty(&Wrapper { elf: fingerprint })?)
}

fn validate_runtime_evidence(path: &Path, profile: &BuildProfile) -> Result<()> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("reading runtime evidence {}", path.display()))?;
    let mut saw_ready = false;
    let mut saw_entry = false;
    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_str(line)
            .with_context(|| format!("runtime evidence line {} is not JSON", index + 1))?;
        let event = record.get("event").and_then(serde_json::Value::as_str);
        match event {
            Some("ready") => {
                ensure!(
                    record.get("profile_id").and_then(serde_json::Value::as_str)
                        == Some(profile.profile_id.as_str()),
                    "runtime evidence profile_id does not match {}",
                    profile.profile_id
                );
                ensure!(
                    record
                        .get("mutation_allowed")
                        .and_then(serde_json::Value::as_bool)
                        == Some(false),
                    "approval evidence must come from a passive probe"
                );
                saw_ready = true;
            }
            Some("enter") => {
                ensure!(
                    record
                        .get("hook")
                        .and_then(serde_json::Value::as_str)
                        .is_some(),
                    "runtime entry evidence is missing hook"
                );
                ensure!(
                    record
                        .get("thread_id")
                        .and_then(serde_json::Value::as_u64)
                        .is_some(),
                    "runtime entry evidence is missing thread_id"
                );
                saw_entry = true;
            }
            _ => {}
        }
    }
    ensure!(saw_ready, "runtime evidence has no passive ready record");
    ensure!(saw_entry, "runtime evidence has no observed hook entry");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghidra_wrapper_keeps_arguments_separate() {
        let args = ghidra_scan_args(
            Path::new("/tmp/PalServer"),
            Path::new("/tmp/evidence with spaces.json"),
            &["RequestAddItem_ToServer".to_owned()],
        );
        assert_eq!(args[0], OsString::from("/tmp/PalServer"));
        assert_eq!(args[1], OsString::from("/tmp/evidence with spaces.json"));
        assert_eq!(args[2], OsString::from("RequestAddItem_ToServer"));
    }

    #[test]
    fn runtime_evidence_must_match_profile_and_be_passive() {
        let profile = BuildProfile::candidate(
            "1",
            ElfFingerprint {
                sha256: format!("aa{}", "00".repeat(31)),
                build_id: "11".repeat(8),
                machine: "x86_64".to_owned(),
                bits: 64,
                endian: "little".to_owned(),
                elf_type: "ET_EXEC".to_owned(),
                image_base: 0x20_0000,
                file_size: 1,
            },
        );
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let evidence = format!(
            "{{\"event\":\"ready\",\"profile_id\":\"{}\",\"mutation_allowed\":false}}\n\
             {{\"event\":\"enter\",\"hook\":\"request.exec-thunk\",\"thread_id\":9}}\n",
            profile.profile_id
        );
        fs::write(temporary.path(), evidence).unwrap();
        assert!(validate_runtime_evidence(temporary.path(), &profile).is_ok());
    }
}
