.PHONY: check
check:
	@cd kernel && \
	echo "Checking clippy" && \
	cargo clippy -- -D warnings && \
	echo "Checking formatting" && \
	cargo fmt --check

.PHONY: build
build:
	@cd kernel && cargo build --features "strict"

.PHONY: run
run:
	@cd kernel && cargo run

.PHONY: run-term
run-term:
	@cd kernel && cargo run mode terminal

.PHONY: gdb-term
gdb-term:
	@cd kernel && cargo run mode gdb-terminal

.PHONY: gdb-gui
gdb-gui:
	@cd kernel && cargo run mode gdb-gui

.PHONY: test
test:
	@cd kernel && cargo test

.PHONY: fmt
fmt:
	@cd kernel && cargo fmt

.PHONY: clean
clean:
	@cd kernel && cargo clean