# Nuke built-in rules and variables.
override MAKEFLAGS += -rR

override IMAGE_NAME := taos

UNAME_S := $(shell uname -s)
UNAME_P := $(shell uname -p)
UNAME_P := $(shell uname -p)

# QEMU configuration
ifeq ($(UNAME_S),Linux)
	QEMU_MACHINE = -M q35,accel=kvm,dump-guest-core=off
else 
	ifeq ($(UNAME_P),x86_64)
		QEMU_MACHINE = -M q35,accel=hvf
	else 
		QEMU_MACHINE = -M q35
	endif
endif

# QEMU configuration
QEMU := qemu-system-x86_64
QEMU_MEMORY := -m 4G

ifeq ($(UNAME_P),x86_64)
QEMU_CPU := -smp 2 -cpu host,+x2apic,+invtsc
endif
ifneq ($(filter arm%,$(UNAME_P)),)
QEMU_CPU := -smp 2 -cpu Conroe-v1,+x2apic,+invtsc
endif

QEMU_NET := -netdev user,id=net0 -device virtio-net-pci,netdev=net0
QEMU_AUDIO := -device intel-hda -device hda-duplex
QEMU_GRAPHICS := -vga std
QEMU_GDB := -s -S

# Common QEMU flags groups
QEMU_COMMON := $(QEMU_MACHINE) $(QEMU_MEMORY) $(QEMU_CPU) $(QEMU_NET) $(QEMU_AUDIO) $(QEMU_GRAPHICS)
QEMU_UEFI := $(QEMU_COMMON) -drive if=pflash,unit=0,format=raw,file=ovmf/ovmf-code-x86_64.fd,readonly=on -drive if=pflash,unit=1,format=raw,file=ovmf/ovmf-vars-x86_64.fd
QEMU_BIOS := $(QEMU_COMMON)

# Boot media flags
QEMU_BOOT_ISO := -cdrom $(IMAGE_NAME).iso -boot d
QEMU_BOOT_HDD := -hda $(IMAGE_NAME).hdd

# Display flags
QEMU_DISPLAY_GUI :=
QEMU_DISPLAY_TERM := -nographic

.PHONY: all
all: $(IMAGE_NAME).iso

.PHONY: all-hdd
all-hdd: $(IMAGE_NAME).hdd

.PHONY: run
run: run-gui

.PHONY: run-gui
run-gui: ovmf/ovmf-code-x86_64.fd ovmf/ovmf-vars-x86_64.fd $(IMAGE_NAME).iso
	$(QEMU) $(QEMU_UEFI) $(QEMU_BOOT_ISO) $(QEMU_DISPLAY_GUI)

.PHONY: run-term
run-term: ovmf/ovmf-code-x86_64.fd ovmf/ovmf-vars-x86_64.fd $(IMAGE_NAME).iso
	$(QEMU) $(QEMU_UEFI) $(QEMU_BOOT_ISO) $(QEMU_DISPLAY_TERM)

.PHONY: run-hdd-gui
run-hdd-gui: ovmf/ovmf-code-x86_64.fd ovmf/ovmf-vars-x86_64.fd $(IMAGE_NAME).hdd
	$(QEMU) $(QEMU_UEFI) $(QEMU_BOOT_HDD) $(QEMU_DISPLAY_GUI)

.PHONY: run-hdd-term
run-hdd-term: ovmf/ovmf-code-x86_64.fd ovmf/ovmf-vars-x86_64.fd $(IMAGE_NAME).hdd
	$(QEMU) $(QEMU_UEFI) $(QEMU_BOOT_HDD) $(QEMU_DISPLAY_TERM)

.PHONY: run-bios
run-bios: $(IMAGE_NAME).iso
	$(QEMU) $(QEMU_BIOS) $(QEMU_BOOT_ISO) $(QEMU_DISPLAY_GUI)

.PHONY: run-hdd-bios
run-hdd-bios: $(IMAGE_NAME).hdd
	$(QEMU) $(QEMU_BIOS) $(QEMU_BOOT_HDD) $(QEMU_DISPLAY_GUI)

# Debug targets
.PHONY: gdb-gui
gdb-gui: ovmf/ovmf-code-x86_64.fd ovmf/ovmf-vars-x86_64.fd $(IMAGE_NAME).iso
	$(QEMU) $(QEMU_UEFI) $(QEMU_BOOT_ISO) $(QEMU_DISPLAY_GUI) $(QEMU_GDB)

.PHONY: gdb-term
gdb-term: ovmf/ovmf-code-x86_64.fd ovmf/ovmf-vars-x86_64.fd $(IMAGE_NAME).iso
	$(QEMU) $(QEMU_UEFI) $(QEMU_BOOT_ISO) $(QEMU_DISPLAY_TERM) $(QEMU_GDB)

ovmf/ovmf-code-x86_64.fd:
	mkdir -p ovmf
	curl -Lo $@ https://github.com/osdev0/edk2-ovmf-nightly/releases/latest/download/ovmf-code-x86_64.fd

ovmf/ovmf-vars-x86_64.fd:
	mkdir -p ovmf
	curl -Lo $@ https://github.com/osdev0/edk2-ovmf-nightly/releases/latest/download/ovmf-vars-x86_64.fd

limine/limine:
	rm -rf limine
	git clone https://github.com/limine-bootloader/limine.git --branch=v8.x-binary --depth=1
	$(MAKE) -C limine

.PHONY: kernel
kernel:
	$(MAKE) -C kernel

$(IMAGE_NAME).iso: limine/limine kernel
	rm -rf iso_root
	mkdir -p iso_root/boot
	cp -v kernel/kernel iso_root/boot/
	mkdir -p iso_root/boot/limine
	cp -v limine.conf iso_root/boot/limine/
	mkdir -p iso_root/EFI/BOOT
	cp -v limine/limine-bios.sys limine/limine-bios-cd.bin limine/limine-uefi-cd.bin iso_root/boot/limine/
	cp -v limine/BOOTX64.EFI iso_root/EFI/BOOT/
	cp -v limine/BOOTIA32.EFI iso_root/EFI/BOOT/
	xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin \
		-no-emul-boot -boot-load-size 4 -boot-info-table \
		--efi-boot boot/limine/limine-uefi-cd.bin \
		-efi-boot-part --efi-boot-image --protective-msdos-label \
		iso_root -o $(IMAGE_NAME).iso
	./limine/limine bios-install $(IMAGE_NAME).iso
	rm -rf iso_root

$(IMAGE_NAME).hdd: limine/limine kernel
	rm -f $(IMAGE_NAME).hdd
	dd if=/dev/zero bs=1M count=0 seek=64 of=$(IMAGE_NAME).hdd
	sgdisk $(IMAGE_NAME).hdd -n 1:2048 -t 1:ef00
	./limine/limine bios-install $(IMAGE_NAME).hdd
	mformat -i $(IMAGE_NAME).hdd@@1M
	mmd -i $(IMAGE_NAME).hdd@@1M ::/EFI ::/EFI/BOOT ::/boot ::/boot/limine
	mcopy -i $(IMAGE_NAME).hdd@@1M kernel/kernel ::/boot
	mcopy -i $(IMAGE_NAME).hdd@@1M limine.conf ::/boot/limine
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/limine-bios.sys ::/boot/limine
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/BOOTX64.EFI ::/EFI/BOOT
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/BOOTIA32.EFI ::/EFI/BOOT

.PHONY: clean
clean:
	$(MAKE) -C kernel clean
	rm -rf iso_root $(IMAGE_NAME).iso $(IMAGE_NAME).hdd

.PHONY: distclean
distclean: clean
	$(MAKE) -C kernel distclean
	rm -rf limine ovmf