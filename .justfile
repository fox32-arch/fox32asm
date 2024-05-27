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
	/bin/just --list

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
fmt:
	#!/usr/bin/env bash
	set -euo pipefail
	cargo fmt

# Check Rustfmt for the code
[no-exit-message]
lint *ARGS:
	#!/usr/bin/env bash
	set -euo pipefail
	cargo clippy {{ARGS}}

# Run lint workflow using Clippy
[no-exit-message]
analyze:
	#!/usr/bin/env bash
	set -euo pipefail
	cargo clippy

# Build ZIP releases in GitHub actions
[no-exit-message]
[private]
release:
	#!/usr/bin/env bash
	set -euo pipefail
	lune run release




	