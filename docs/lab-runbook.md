# Disposable Linux lab runbook

The lab must never share save data, ports, credentials, service units, or plugin
directories with your production server. Keep the production deployment
stopped from this workflow entirely.

## Host preflight

1. Use the pinned Linux depot manifest recorded in the candidate build profile,
   plus mounted Steam runtime depot `1006`; downloading only depot `2394012`
   omits the `linux64/steamclient.so` used by the official launch script.
2. Put the lab under a user-owned cache directory, not inside this repository.
3. Ensure at least 12 GiB of available memory before starting PalServer. Full
   Ghidra analysis separately requires 16 GiB available and refuses to run while
   either the Palworld client or PalServer is active.
4. Bind loopback or an isolated firewall namespace and use disposable ports.
5. Use a fresh empty save directory and a randomly generated admin password.

## Harness

The lab is driven entirely through `make` targets (run `make help`), backed by
scripts under `scripts/`:

| target | script | what it does |
|--------|--------|--------------|
| `make lab-preflight` | `lab-preflight.sh` | check identity, steamclient staging, ELF fingerprint, ≥12 GiB free, no stale socket |
| `make lab-observe` | `lab-observe.sh` → `observe_live.py` | launch PalServer as an owned child, verify every profile anchor against live `/proc/<pid>/mem`, then stop it (read-only, safe on the candidate) |
| `make lab-start` / `lab-status` / `lab-stop` / `lab-logs` | `lab-server.sh` | daemonized server lifecycle |

`scripts/lab-env.sh` isolates `HOME`/XDG under `~/.cache/palmod/lab-home`;
`scripts/lab-lib.sh` holds shared launch/readiness/stop helpers. Override
`PALMOD_LAB_PORT` and `PALMOD_LAB_READY_TIMEOUT` as needed. The observer must
*own* the server process: under yama `ptrace_scope=1` only an ancestor may read
`/proc/<pid>/mem`, which is why `observe_live.py` launches it directly.

## Research stages

1. Fingerprint the ELF and run structural discovery (`make reverse-verify`,
   `reverse/bin/scan_elf.py`); optional deep decompile with `decode_abi.py`.
2. Review corroborated evidence and candidate addresses.
3. Confirm the candidate against the live process: `make lab-observe` verifies
   anchors byte-exact in the running server. Deeper passive probes (call
   frequency, thread identity) come next; Frida is optional here.
4. Promote each symbol only after static and dynamic evidence agree.
5. Run the fake-server harness before any real-server mutation.
6. Start PalServer through `palmod-run` with a validated profile and no plugins.
7. Enable the read-only event path, then command suppression, then a harmless
   action, and only then the `GiveItem` vertical slice.

Any mismatch, unexpected call frequency, invalid pointer range, or game-thread
violation ends that validation run. A candidate is not made "close enough" by
weakening checks.

## Production gate

Production deployment is a separate, explicit operation. It requires a pinned
artifact, validated profile for the exact live SHA-256, backup/restore test,
canary restart, health checks, and a documented way to launch without preload.
Nothing in the lab workflow writes to your production server tree; set
`PALMOD_PRODUCTION_TREE` to that path so the lab refuses to run against it (or
any path beneath it).
