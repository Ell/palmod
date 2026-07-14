# Pinned toolchain

Reproducing results requires pinning analysis tools as carefully as the server
build. The local development setup currently uses:

| Component | Version / identity |
| --- | --- |
| Palworld dedicated server | Steam app `2394010`, Linux depot `2394012`, build `24088465`, manifest `3392720560779800260`; mounted Steam runtime depot `1006`, manifest `6403079453713498174` |
| PalServer ELF | GNU build ID `217802a00653a9c4`, SHA-256 `a05788ead7619db22a1509c43241c16d289ed7040e8bcbb2e36e13e223e822f9` |
| Ghidra | `12.1.2_PUBLIC_20260605`, archive SHA-256 `b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d` |
| Java for Ghidra | OpenJDK 21 |
| Frida CLI / Gum devkit | `17.6.2`, glibc x86-64 devkit SHA-256 `a5cb58cb6282e27204e54c4a7b52fca1f891ab1d5d6379789ba12d489ca51125` |
| Lua | `5.4.8` |
| Rust | stable `1.95.0` via `rust-toolchain.toml` |
| Native build | Clang 17, CMake 4.x, Ninja 1.13 |
| UE4SS reference | `c2ac246447a8bcd92541070cb474044e7a2bbbe6` |
| patternsleuth reference | `fd48670daac28202301f10d487d051f262bc28c8` |

Large and redistributability-sensitive inputs live outside Git:

```text
~/.cache/palmod/lab/24088465/
~/.local/share/palmod/tools/ghidra_12.1.2_PUBLIC/
~/.local/share/palmod/tools/frida-gum-devkit-17.6.2-linux-x86_64/
```

The repository contains hashes and installers, not copies of these artifacts.
Always set `JAVA_HOME=/usr/lib/jvm/java-21-openjdk` for headless Ghidra; the host
default JVM may be newer than Ghidra's supported range. The checked-in wrapper
also caps Ghidra at a 6 GiB heap, four active processors, and idle-class I/O.
