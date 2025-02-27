override STORAGE_NAME := storage_test

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

.PHONY: objdump
objdump:
	@cd kernel && cargo objdump --lib --release -- -d -M intel

.PHONY: blank_drive
blank_drive:
	@cd kernel && dd if=/dev/zero of=$(STORAGE_NAME).img bs=1M count=4k

.PHONY: clean
clean:
	@cd kernel && rm $(STORAGE_NAME).img
	@cd kernel && cargo clean
