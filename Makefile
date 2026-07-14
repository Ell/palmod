.DEFAULT_GOAL := help

# Bounded parallelism keeps builds friendly on a workstation also running a lab.
PALMOD_BUILD_JOBS ?= 2
export CARGO_BUILD_JOBS := $(PALMOD_BUILD_JOBS)

# Lab / reversing knobs (override on the command line, e.g. SERVER_BINARY=/path).
SERVER_BINARY  ?= $(HOME)/.cache/palmod/lab/24088465/Pal/Binaries/Linux/PalServer-Linux-Shipping
VERIFY_PROFILE ?= profiles/candidates/palworld-linux-24088465.toml

.PHONY: help build rust-build native-configure native-build dist \
        test rust-test native-test reverse-test reverse-verify check clean \
        lab-preflight lab-observe lab-probe lab-capture lab-reflect lab-dump \
        reflect-check lab-recover-engine lab-start lab-stop lab-status lab-logs

## help: list the documented targets (default)
help:
	@echo "Palmod make targets:"
	@grep -hE '^##[[:space:]]' $(MAKEFILE_LIST) | sed 's/^## /  /'
	@echo
	@echo "Overridable vars: PALMOD_BUILD_JOBS, SERVER_BINARY, VERIFY_PROFILE,"
	@echo "  PALMOD_LAB_PORT, PALMOD_LAB_READY_TIMEOUT (see scripts/lab-*.sh)."

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

## build: build the Rust workspace and the native loader
build: rust-build native-build

rust-build:
	nice -n 10 cargo build --workspace

native-configure:
	cmake -S native -B build/native -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DPALMOD_BUILD_TESTS=ON

native-build: native-configure
	nice -n 10 cmake --build build/native --parallel $(PALMOD_BUILD_JOBS)

## dist: build a self-contained release tarball in dist/ (binaries, loader, profiles, plugins)
dist:
	nice -n 10 cargo build --release -p palmod-run -p palmodctl
	$(MAKE) native-build
	scripts/make-dist.sh

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

## test: run all Rust, native, and reverse-pipeline tests
test: rust-test native-test reverse-test

rust-test:
	nice -n 10 cargo test --workspace --all-features -- --test-threads=$(PALMOD_BUILD_JOBS)

native-test: native-build
	ctest --test-dir build/native --output-on-failure

reverse-test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=reverse python -m unittest discover -s reverse/tests -v

## check: build, test, and run fmt/clippy/shell/whitespace gates
check: build test
	cargo fmt --all --check
	nice -n 10 cargo clippy --workspace --all-targets --all-features -- -D warnings
	bash -n scripts/*.sh
	git diff --check

# ---------------------------------------------------------------------------
# Reversing / lab (need the disposable server; no-ops or skips without it)
# ---------------------------------------------------------------------------

## reverse-verify: static gate — verify a profile against the ELF (no server)
reverse-verify:
	@if [ -f "$(SERVER_BINARY)" ]; then \
		PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=reverse python reverse/bin/verify_profile.py "$(VERIFY_PROFILE)" "$(SERVER_BINARY)"; \
	else \
		echo "reverse-verify: server ELF not present at $(SERVER_BINARY); skipping (set SERVER_BINARY=...)"; \
	fi

## lab-preflight: check lab identity, staging, and host capacity
lab-preflight:
	scripts/lab-preflight.sh

## lab-observe: launch a child server and verify anchors against live memory
lab-observe:
	scripts/lab-observe.sh "$(VERIFY_PROFILE)"

## lab-probe: locate live UFunction::Func swap targets in the running server
lab-probe:
	scripts/lab-probe.sh "$(VERIFY_PROFILE)"

## lab-capture: run the server under gdb and capture EnterChat chat strings
lab-capture:
	scripts/lab-capture.sh

## lab-reflect: recover reflection-layout globals from the live server
lab-reflect:
	scripts/lab-run.sh reverse/bin/find_reflection.py

## lab-dump: generate our own reflection mappings (JSON w/ offsets) from the server
lab-dump:
	scripts/lab-run.sh reverse/bin/dump_reflection.py

## reflect-check: cross-check runtime's hardcoded facts against the dump (no server)
reflect-check:
	python reverse/bin/gen_facts.py --check

## lab-recover-engine: recover engine/inheritance facts for the profile (SuperStruct
## offset, GEngine VA, UEngine::Tick slot) — needs a running lab server + ptrace_scope=0
lab-recover-engine:
	PYTHONPATH=reverse python reverse/bin/recover_engine_facts.py

## lab-start: start the disposable lab server (daemonized)
lab-start:
	scripts/lab-server.sh start

## lab-stop: stop the disposable lab server
lab-stop:
	scripts/lab-server.sh stop

## lab-status: report lab server state, pid, rss, and port
lab-status:
	scripts/lab-server.sh status

## lab-logs: tail the lab server log
lab-logs:
	scripts/lab-server.sh logs

## clean: remove Rust and native build artifacts
clean:
	cargo clean
	cmake -E remove_directory build
