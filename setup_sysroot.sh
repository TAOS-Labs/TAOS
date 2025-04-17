#!/bin/bash
set -euo pipefail

# Ensure system architecture is x86_64
ARCH="$(uname -m)"
if [[ "${ARCH}" != "x86_64" ]]; then
	echo "This script only supports x86_64 architecture"
	exit 1
fi

SYSROOT="$HOME/linux_sysroot"
MUSL_VERSION="1.2.5"
MUSL_TAR="musl-${MUSL_VERSION}.tar.gz"
MUSL_URL="https://musl.libc.org/releases/${MUSL_TAR}"

# Create sysroot and build dirs
echo "Creating sysroot directory at ${SYSROOT}..."
mkdir -p "${SYSROOT}"
BUILD_DIR="$(mktemp -d)"
echo "Using build directory: ${BUILD_DIR}"

# Download musl tar
echo "Downloading and extracting musl ${MUSL_VERSION}..."
curl -LO "${MUSL_URL}"
tar -xf "${MUSL_TAR}" -C "${BUILD_DIR}"
cd "${BUILD_DIR}/musl-${MUSL_VERSION}"

# configure for static linking
echo "Configuring musl..."
./configure --prefix=/usr --sysroot=~/linux_sysroot --disable-shared
make && make install DESTDIR=~/linux_sysroot

# Update musl-gcc wrapper to point to the correct specs file
echo "Updating musl-gcc wrapper..."
MUSL_GCC_PATH="${SYSROOT}/usr/bin/musl-gcc"
if [ -f "${MUSL_GCC_PATH}" ]; then
	"${SYSROOT}/usr/bin/musl-gcc" -dumpspecs >"${SYSROOT}/usr/lib/musl-gcc.specs"
	sed -i 's|exec "${REALGCC:-gcc}" "$@" -specs "/usr/lib/musl-gcc.specs"|"${REALGCC:-gcc}" "$@" -specs "'${SYSROOT}'/usr/lib/musl-gcc.specs"|g' "${MUSL_GCC_PATH}"
else
	echo "musl-gcc wrapper not found at ${MUSL_GCC_PATH}"
fi

# Clean up build directory and tarball
echo "Cleaning up..."
rm -rf "${BUILD_DIR}"
rm -f "${MUSL_TAR}"

echo "Sysroot setup complete at ${SYSROOT}."
echo "You can now statically compile C programs using musl by invoking:"
echo "  ${SYSROOT}/usr/bin/musl-gcc -static -o your_program your_program.c"
