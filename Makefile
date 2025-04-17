override STORAGE_NAME := storage_test

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
		MKFS := mkfs.ext2
endif
ifeq ($(UNAME_S),Darwin)
		MKFS := $(shell brew --prefix e2fsprogs)/sbin/mkfs.ext2
endif

.PHONY: check
check:
	@cd kernel && \
	echo "Checking clippy" && \
	cargo clippy --all-targets -- -D warnings && \
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
	@cd kernel && cargo objdump --lib --release -- -d -M intel -S

.PHONY: blank_drive
blank_drive:
	@cd kernel && dd if=/dev/zero of=$(STORAGE_NAME).img bs=1M count=4k
	@cd kernel && $(MKFS) -b 1024 -d ../resources -I 128 $(STORAGE_NAME).img 4g

.PHONY: clean
clean:
	@cd kernel && rm -f $(STORAGE_NAME).img
	@cd kernel && cargo clean
