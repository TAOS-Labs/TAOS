#!/bin/bash

# Check if an argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <assembly_file>"
    exit 1
fi

# Store the argument
ASM_FILE="$1"

# Navigate to the target directory
pushd ./kernel/src/processes/test_binaries/ || exit

# Assemble the file using nasm
nasm -f elf64 "$ASM_FILE.asm" -o "$ASM_FILE.o"

# Link the object file
ld "$ASM_FILE.o" -o "$ASM_FILE"

# Remove the object file
rm -rf "$ASM_FILE.o"

# Navigate back to the root directory
popd || exit