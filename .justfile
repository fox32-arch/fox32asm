CWD := invocation_directory()
BIN_NAME := "fox32asm"

# Lists the available recipes
[no-cd]
[no-exit-message]
[private]
default:
	#!/usr/bin/env bash
	set -euo pipefail
	printf "Current directory:\n    {{CWD}}\n"
	just --list

# Builds the assembler binary
[no-exit-message]
build *ARGS:
	#!/usr/bin/env bash
	set -euo pipefail
	cargo build --bin {{BIN_NAME}} {{ARGS}}

# Run tests for the assembler
[no-exit-message]
test *ARGS:
	#!/usr/bin/env bash
	set -euo pipefail
	cargo test -- --test-threads=1 {{ARGS}}

# Apply Rustfmt to the code
[no-exit-message]
fmt *ARGS:
	#!/usr/bin/env bash
	set -euo pipefail
	cargo fmt {{ARGS}}

# Check Rustfmt for the code
[no-exit-message]
lint *ARGS:
	#!/usr/bin/env bash
	set -euo pipefail
	cargo clippy {{ARGS}}

# Build ZIP releases in GitHub actions
[no-exit-message]
[private]
build-release:
	#!/usr/bin/env bash
	set -euo pipefail
	lune run release




	