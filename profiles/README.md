# Compatibility profiles

A profile describes one exact server build: its ELF fingerprint, the anchor
preimage bytes the loader re-checks at launch, and the reflection facts (roots,
offsets, name-pool location) the runtime needs. It carries no hook/function
catalog — hooks are resolved live by UFunction name at runtime, so any of the
game's reflected UFunctions can be hooked without per-function config. There is no signing or
trusted keys — correctness comes from matching the exact binary, not from who
authored the file. If the running server does not byte-match a profile, the
loader refuses to hook it (the server just runs vanilla), so a wrong profile can
never corrupt a mismatched build.

## Layout

- **`*.toml` (top level)** — shipped, `validated` profiles. This is the directory
  `palmod-run --profiles` scans by default, and what the release tarball bundles.
  One file per supported server build.
- **`candidates/`** — reverse-engineering output under review. These are marked
  `status = "candidate"`; the loader rejects them. This is the staging area a new
  build goes through before promotion.
- **`evidence/`** — supporting static/dynamic evidence for a candidate.

## Supported builds

| Build (Steam) | File | Notes |
|---|---|---|
| `24088465` | `palworld-linux-24088465.toml` | UE 5.1.1; reflection facts live-validated |

## Adding a profile for another server build

1. Produce a candidate for the build (see [../docs/reversing.md](../docs/reversing.md)
   and the `make lab-*` pipeline).
2. Promote it with `palrev approve`, which verifies the fingerprint, the static
   anchor bytes, and a passive build-matched runtime probe, then writes a
   `validated` profile:

   ```sh
   palrev approve \
     --candidate profiles/candidates/<build>.toml \
     --binary /path/to/PalServer-Linux-Shipping \
     --runtime-evidence <probe.ndjson> \
     --output profiles/<build>.toml
   ```

3. Drop the resulting `.toml` in this directory. `palmod-run` will select it
   automatically for any server whose bytes match.
