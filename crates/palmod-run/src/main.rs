use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use palmod_profile::{BuildProfile, ElfFingerprint, ProfileStatus, fingerprint_path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

const DEFAULT_CRASH_LIMIT: usize = 3;
const DEFAULT_CRASH_WINDOW_SECONDS: u64 = 600;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Direct path to PalServer-Linux-Shipping. PalServer.sh is intentionally rejected.
    #[arg(long)]
    server: PathBuf,
    #[arg(long, default_value = "profiles")]
    profiles: PathBuf,
    #[arg(long, default_value = "build/native/libpalmod.so")]
    library: PathBuf,
    #[arg(long, default_value = "plugins")]
    plugin_dir: PathBuf,
    #[arg(long, default_value = ".palmod-state")]
    state_dir: PathBuf,
    #[arg(long, env = "PALMOD_CONTROL_SOCKET")]
    control_socket: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_CRASH_LIMIT)]
    crash_limit: usize,
    #[arg(long, default_value_t = DEFAULT_CRASH_WINDOW_SECONDS)]
    crash_window_seconds: u64,
    /// Clear this build profile's persistent crash quarantine before launch.
    #[arg(long)]
    clear_quarantine: bool,
    /// Fail instead of starting vanilla when no exact profile exists.
    #[arg(long)]
    require_profile: bool,
    /// Arguments passed after `PalServer`'s mandatory `Pal` argument.
    #[arg(last = true)]
    server_args: Vec<OsString>,
}

#[derive(Debug)]
enum Selection {
    Verified {
        profile: Box<BuildProfile>,
        path: PathBuf,
    },
    Unsupported(String),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct QuarantineState {
    #[serde(default)]
    profiles: BTreeMap<String, CrashRecord>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct CrashRecord {
    #[serde(default)]
    failures_unix_seconds: Vec<u64>,
    #[serde(default)]
    quarantined_at_unix_seconds: Option<u64>,
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(status) => exit_code(status),
        Err(error) => {
            eprintln!("palmod-run: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: &Cli) -> Result<ExitStatus> {
    ensure!(cli.crash_limit > 0, "--crash-limit must be non-zero");
    ensure!(
        cli.crash_window_seconds > 0,
        "--crash-window-seconds must be non-zero"
    );

    let server = preflight_server(&cli.server)?;
    let server_root = infer_server_root(&server)?;
    prepare_steamclient(&server_root)?;
    let fingerprint = fingerprint_path(&server)?;
    let selection = select_profile(&cli.profiles, &fingerprint)?;

    let state_dir = create_and_canonicalize_private_dir(&cli.state_dir, "state directory")?;
    let quarantine_path = state_dir.join("quarantine.json");
    let mut quarantine = load_quarantine(&quarantine_path)?;
    let now = unix_seconds()?;

    let mut active = match selection {
        Selection::Verified { profile, path } => {
            let quarantined = {
                let record = quarantine
                    .profiles
                    .entry(profile.profile_id.clone())
                    .or_default();
                prune_failures(record, now, cli.crash_window_seconds);
                if cli.clear_quarantine {
                    *record = CrashRecord::default();
                }
                record.quarantined_at_unix_seconds.is_some()
            };
            if cli.clear_quarantine {
                save_quarantine(&quarantine_path, &quarantine)?;
            }
            if quarantined {
                eprintln!(
                    "palmod-run: profile {} is crash-quarantined; starting vanilla (use --clear-quarantine after investigation)",
                    profile.profile_id
                );
                None
            } else {
                Some((profile, path))
            }
        }
        Selection::Unsupported(reason) => {
            if cli.require_profile {
                bail!("no supported profile: {reason}");
            }
            eprintln!("palmod-run: {reason}; starting vanilla with no injected library");
            None
        }
    };

    let (mut child, active_profile, profile_memfd) = if let Some((profile, path)) = active.take() {
        // Recheck all static preimages immediately before the launch handoff.
        profile
            .verify_anchor_bytes(&server)
            .with_context(|| format!("profile {} anchor verification", profile.profile_id))?;
        let library = canonical_file(&cli.library, "native library")?;
        let plugin_dir = canonical_dir(&cli.plugin_dir, "plugin directory")?;
        let requested_socket = cli
            .control_socket
            .clone()
            .map_or_else(default_control_socket, Ok)?;
        let control_socket = canonical_socket_path(&requested_socket)?;
        let (profile_memfd, profile_digest) = sealed_profile_memfd(&profile)?;

        let mut command = server_command(&server, &server_root, &cli.server_args);
        command
            .env("PALMOD_PROFILE_FD", profile_memfd.as_raw_fd().to_string())
            .env("PALMOD_PROFILE_SHA256", &profile_digest)
            .env("PALMOD_PROFILE_ID", &profile.profile_id)
            .env("PALMOD_PLUGIN_DIR", &plugin_dir)
            .env("PALMOD_CONTROL_SOCKET", &control_socket)
            .env("PALMOD_STATE_DIR", &state_dir)
            .env("PALMOD_LAUNCHER_VERSION", env!("CARGO_PKG_VERSION"))
            .env("LD_PRELOAD", merged_preload(&library));
        eprintln!(
            "palmod-run: launching build {} with validated profile {} ({})",
            profile.steam_build_id,
            profile.profile_id,
            path.display()
        );
        let child = command
            .spawn()
            .with_context(|| format!("launching {}", server.display()))?;
        (child, Some(profile.profile_id), Some(profile_memfd))
    } else {
        let child = server_command(&server, &server_root, &cli.server_args)
            .spawn()
            .with_context(|| format!("launching vanilla {}", server.display()))?;
        (child, None, None)
    };

    // The child inherited this non-CLOEXEC descriptor. Closing the launcher's copy
    // after spawn prevents it from extending the memfd lifetime unnecessarily.
    drop(profile_memfd);
    let (status, planned_shutdown) = wait_with_signal_forwarding(&mut child)?;

    if let Some(profile_id) = active_profile {
        let record = quarantine.profiles.entry(profile_id.clone()).or_default();
        if status.success() || planned_shutdown {
            record.failures_unix_seconds.clear();
        } else {
            record.failures_unix_seconds.push(unix_seconds()?);
            prune_failures(record, unix_seconds()?, cli.crash_window_seconds);
            if record.failures_unix_seconds.len() >= cli.crash_limit {
                record.quarantined_at_unix_seconds = Some(unix_seconds()?);
                eprintln!(
                    "palmod-run: quarantined profile {profile_id} after {} failures in {} seconds",
                    record.failures_unix_seconds.len(),
                    cli.crash_window_seconds
                );
            }
        }
        save_quarantine(&quarantine_path, &quarantine)?;
    }
    Ok(status)
}

fn preflight_server(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.file_name()
            .is_some_and(|name| name == "PalServer-Linux-Shipping"),
        "--server must name PalServer-Linux-Shipping directly; never pass PalServer.sh"
    );
    let server = canonical_file(path, "PalServer executable")?;
    let mode = fs::metadata(&server)?.permissions().mode();
    ensure!(
        mode & 0o111 != 0,
        "PalServer binary is not executable: {} (fix with chmod +x)",
        server.display()
    );
    Ok(server)
}

fn infer_server_root(server: &Path) -> Result<PathBuf> {
    let linux = server.parent().context("PalServer binary has no parent")?;
    let binaries = linux.parent().context("missing Pal/Binaries directory")?;
    let pal = binaries.parent().context("missing Pal directory")?;
    let root = pal.parent().context("missing server root")?;
    ensure!(
        linux.file_name().is_some_and(|name| name == "Linux"),
        "binary is not below Pal/Binaries/Linux"
    );
    ensure!(
        binaries.file_name().is_some_and(|name| name == "Binaries"),
        "binary is not below Pal/Binaries/Linux"
    );
    ensure!(
        pal.file_name().is_some_and(|name| name == "Pal"),
        "binary is not below Pal/Binaries/Linux"
    );
    root.canonicalize()
        .with_context(|| format!("resolving server root {}", root.display()))
}

fn prepare_steamclient(root: &Path) -> Result<()> {
    let source = root.join("linux64/steamclient.so");
    ensure!(
        source.is_file(),
        "Steam depot 1006 runtime is absent: expected {}",
        source.display()
    );
    let destination = root.join("Pal/Binaries/Linux/steamclient.so");
    if destination.exists() {
        ensure!(
            !fs::symlink_metadata(&destination)?.file_type().is_symlink(),
            "steamclient destination may not be a symlink: {}",
            destination.display()
        );
        ensure!(
            destination.is_file(),
            "steamclient destination is not a file: {}",
            destination.display()
        );
        ensure!(
            sha256_path(&source)? == sha256_path(&destination)?,
            "existing {} differs from depot runtime {}; refusing overwrite",
            destination.display(),
            source.display()
        );
        return Ok(());
    }

    let mut input = File::open(&source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .with_context(|| format!("creating {} without overwrite", destination.display()))?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    fs::set_permissions(&destination, fs::metadata(&source)?.permissions())?;
    ensure!(
        sha256_path(&source)? == sha256_path(&destination)?,
        "copied steamclient failed hash verification"
    );
    Ok(())
}

fn select_profile(directory: &Path, fingerprint: &ElfFingerprint) -> Result<Selection> {
    ensure!(
        directory.is_dir(),
        "profile directory does not exist: {}",
        directory.display()
    );
    let mut matches = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "toml") {
            continue;
        }
        let profile = BuildProfile::read_toml(&path)
            .with_context(|| format!("loading profile {}", path.display()))?;
        if profile.matches_fingerprint(fingerprint) {
            matches.push((profile, path));
        }
    }
    if matches.is_empty() {
        return Ok(Selection::Unsupported(format!(
            "no exact profile for ELF sha256 {}",
            fingerprint.sha256
        )));
    }
    ensure!(matches.len() == 1, "multiple exact profiles match this ELF");
    let (profile, path) = matches.pop().expect("one matching profile");
    ensure!(
        profile.status == ProfileStatus::Validated,
        "matching profile {} is {:?}, not validated",
        profile.profile_id,
        profile.status
    );
    // Crash-safety is the fingerprint match above plus the anchor-byte
    // verification the caller does before launch. That is the whole gate — no
    // signatures or trusted keys.
    Ok(Selection::Verified {
        profile: Box::new(profile),
        path,
    })
}

fn sealed_profile_memfd(profile: &BuildProfile) -> Result<(File, String)> {
    let bytes = profile.canonical_json_bytes()?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let name = CString::new(format!("palmod-profile-{}", profile.profile_id))?;
    // Deliberately omit CLOEXEC: the verified descriptor is the trust handoff.
    let owned = memfd_create(name.as_c_str(), MFdFlags::MFD_ALLOW_SEALING)?;
    let mut file = File::from(owned);
    file.write_all(&bytes)?;
    file.flush()?;
    fcntl(
        &file,
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_SEAL,
        ),
    )?;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, digest))
}

fn server_command(server: &Path, root: &Path, args: &[OsString]) -> Command {
    let mut command = Command::new(server);
    command
        .current_dir(root)
        .env_remove("LD_PRELOAD")
        .env_remove("PALMOD_PROFILE")
        .env_remove("PALMOD_PROFILE_FD")
        .env_remove("PALMOD_PROFILE_SHA256")
        .env_remove("PALMOD_PROFILE_ID")
        .env_remove("PALMOD_PLUGIN_DIR")
        .env_remove("PALMOD_CONTROL_SOCKET")
        .env_remove("PALMOD_STATE_DIR")
        .arg("Pal")
        .args(args);
    command
}

fn merged_preload(library: &Path) -> OsString {
    let mut value = library.as_os_str().to_owned();
    if let Some(existing) = std::env::var_os("LD_PRELOAD")
        && !existing.is_empty()
    {
        value.push(":");
        value.push(existing);
    }
    value
}

fn wait_with_signal_forwarding(child: &mut Child) -> Result<(ExitStatus, bool)> {
    let child_pid = i32::try_from(child.id()).context("child PID does not fit i32")?;
    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])?;
    let handle = signals.handle();
    let planned_shutdown = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&planned_shutdown);
    let forwarder = std::thread::spawn(move || {
        for raw_signal in signals.forever() {
            if matches!(raw_signal, SIGINT | SIGTERM) {
                observed.store(true, Ordering::Release);
            }
            if let Ok(signal) = Signal::try_from(raw_signal) {
                let _ = kill(Pid::from_raw(child_pid), signal);
            }
        }
    });
    let status = child.wait()?;
    handle.close();
    let _ = forwarder.join();
    Ok((status, planned_shutdown.load(Ordering::Acquire)))
}

fn canonical_file(path: &Path, description: &str) -> Result<PathBuf> {
    ensure!(
        path.is_file(),
        "{description} does not exist: {}",
        path.display()
    );
    path.canonicalize()
        .with_context(|| format!("resolving {}", path.display()))
}

fn canonical_dir(path: &Path, description: &str) -> Result<PathBuf> {
    ensure!(
        path.is_dir(),
        "{description} does not exist: {}",
        path.display()
    );
    path.canonicalize()
        .with_context(|| format!("resolving {}", path.display()))
}

fn create_and_canonicalize_private_dir(path: &Path, description: &str) -> Result<PathBuf> {
    fs::create_dir_all(path)
        .with_context(|| format!("creating {description} {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "{description} may not be a symlink: {}",
        path.display()
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    canonical_dir(path, description)
}

fn canonical_socket_path(path: &Path) -> Result<PathBuf> {
    let filename = path
        .file_name()
        .context("control socket path has no filename")?;
    let parent = path.parent().context("control socket path has no parent")?;
    let parent = create_and_canonicalize_private_dir(parent, "control socket directory")?;
    Ok(parent.join(filename))
}

fn default_control_socket() -> Result<PathBuf> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || PathBuf::from(format!("/run/user/{}", nix::unistd::getuid().as_raw())),
        PathBuf::from,
    );
    ensure!(
        runtime_dir.is_absolute(),
        "XDG_RUNTIME_DIR must be absolute"
    );
    Ok(runtime_dir.join("palmod/control.sock"))
}

fn load_quarantine(path: &Path) -> Result<QuarantineState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                !metadata.file_type().is_symlink(),
                "quarantine state may not be a symlink: {}",
                path.display()
            );
            ensure!(
                metadata.permissions().mode().is_multiple_of(0o100),
                "quarantine state must not be accessible by group/others: {}",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("checking {}", path.display())),
    }
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing quarantine state {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(QuarantineState::default())
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn save_quarantine(path: &Path, state: &QuarantineState) -> Result<()> {
    let parent = path.parent().context("quarantine path has no parent")?;
    let temporary = parent.join(format!(".quarantine-{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating private state file {}", temporary.display()))?;
    file.write_all(&serde_json::to_vec_pretty(state)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn prune_failures(record: &mut CrashRecord, now: u64, window: u64) {
    let earliest = now.saturating_sub(window);
    record
        .failures_unix_seconds
        .retain(|timestamp| *timestamp >= earliest && *timestamp <= now);
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn sha256_path(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn exit_code(status: ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        return u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from);
    }
    eprintln!(
        "palmod-run: PalServer terminated by signal {:?}",
        status.signal()
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn quarantine_uses_sliding_window() {
        let mut record = CrashRecord {
            failures_unix_seconds: vec![1, 500, 999, 1_001],
            quarantined_at_unix_seconds: None,
        };
        prune_failures(&mut record, 1_000, 500);
        assert_eq!(record.failures_unix_seconds, vec![500, 999]);
    }

    #[test]
    fn sealed_profile_descriptor_cannot_be_written() {
        let profile = BuildProfile::candidate(
            "24088465",
            palmod_profile::ElfFingerprint {
                sha256: "aa".repeat(32),
                build_id: "bb".repeat(20),
                machine: "x86_64".to_owned(),
                bits: 64,
                endian: "little".to_owned(),
                elf_type: "ET_EXEC".to_owned(),
                image_base: 0x20_0000,
                file_size: 1,
            },
        );
        let (mut file, digest) = sealed_profile_memfd(&profile).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(file.write_all(b"nope").is_err());
        let flags = fcntl(file.as_fd(), FcntlArg::F_GETFD).unwrap();
        assert_eq!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn infer_root_requires_exact_layout() {
        let root = Path::new("/srv/palworld");
        let binary = root.join("Pal/Binaries/Linux/PalServer-Linux-Shipping");
        assert_eq!(
            infer_server_root_without_io(&binary),
            Some(root.to_path_buf())
        );
        assert_eq!(
            infer_server_root_without_io(Path::new("/tmp/PalServer-Linux-Shipping")),
            None
        );
    }

    #[test]
    fn server_preflight_rejects_non_executable_file() {
        let temporary = tempfile::tempdir().unwrap();
        let linux = temporary.path().join("Pal/Binaries/Linux");
        fs::create_dir_all(&linux).unwrap();
        let binary = linux.join("PalServer-Linux-Shipping");
        fs::write(&binary, b"not really an ELF").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o600)).unwrap();
        let error = preflight_server(&binary).unwrap_err().to_string();
        assert!(error.contains("not executable"));
    }

    fn infer_server_root_without_io(server: &Path) -> Option<PathBuf> {
        let linux = server.parent()?;
        let binaries = linux.parent()?;
        let pal = binaries.parent()?;
        let root = pal.parent()?;
        (linux.file_name()? == "Linux"
            && binaries.file_name()? == "Binaries"
            && pal.file_name()? == "Pal")
            .then(|| root.to_path_buf())
    }
}
