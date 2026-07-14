# Installing Palmod (release tarball)

This is the prebuilt Palmod release. No compiler or build step is required — you
only need a Linux Palworld **dedicated server** already installed.

## 1. Extract

```sh
tar -xzf palmod-*-linux-x86_64.tar.gz
cd palmod-*-linux-x86_64
```

You now have:

```
bin/palmod-run      the launcher (fingerprints your server, installs hooks)
bin/palmodctl       operator CLI for the running server's control socket
lib/libpalmod.so    the in-process loader (LD_PRELOAD'd into the server)
profiles/           shipped compatibility profiles (one .toml per server build)
plugins/            example plugins (give_item, find_item, hook_watch)
run.sh              convenience launcher — fills in the paths for you
```

## 2. Run your server under Palmod

Point `run.sh` at your `PalServer-Linux-Shipping` binary and pass the normal
server arguments after `--`:

```sh
./run.sh --server /path/to/Pal/Binaries/Linux/PalServer-Linux-Shipping \
  -- -port=8211 -useperfthreads -NoAsyncLoadingThread
```

Palmod fingerprints the server binary and looks for a matching profile in
`profiles/`. If one matches, it injects the loader and installs hooks. **If no
profile matches your build, the server starts normally with no hooks** — nothing
is patched. See "Server builds and profiles" below.

To use the operator socket, add `--control-socket /run/palmod.sock`, then:

```sh
bin/palmodctl --socket /run/palmod.sock status
bin/palmodctl --socket /run/palmod.sock plugins.reload
```

## 3. Add or edit plugins

A plugin is a folder under `plugins/` containing `manifest.json` and `main.lua`.
Edit any plugin file and Palmod hot-reloads it within about a second — no
restart. Try the bundled ones in-game (commands use a `!` prefix):

```
!GiveItem Wood <player> 10
!FindItem wood
```

Writing your own plugins is documented in the project's `docs/plugin-api.md`.

## Server builds and profiles

A profile is tied to one exact server build (matched by ELF fingerprint and
verified anchor bytes). The bundled profile targets Steam build **24088465**.
If your server is a different build, drop in a matching profile `.toml`, or
generate one from your binary with the reverse-engineering pipeline in the source
repository (`palrev approve`). Until a matching profile is present, Palmod stays
inert and the server runs vanilla.

## Troubleshooting

- **"no exact profile for ELF …" / server runs vanilla** — your server build has
  no matching profile in `profiles/`. This is by design; add a matching profile.
- **The loader refuses to hook a mismatched build** — also by design: Palmod only
  touches a server whose bytes exactly match a validated profile.
- **Permission denied on run.sh** — `chmod +x run.sh`.

---

Palworld is a trademark of Pocketpair, Inc. This project is independent and does
not distribute game binaries or assets.
