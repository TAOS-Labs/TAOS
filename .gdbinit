set architecture i386:x86-64

target remote localhost:1234
file kernel/target/iso_root/boot/kernel/kernel
# Disable paging for long output
set pagination off