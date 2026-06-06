#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/darwin
mkdir -p build/linux
mkdir -p build/windows

APP_NAME="macadmins_extension"

# copy_bazel_output TARGET DEST copies the single output file of a bazel
# target to DEST. It captures the cquery result, validates that exactly one
# non-empty path was returned, and quotes the path so files with whitespace
# (or an unexpected multi-file output) are handled safely rather than being
# silently word-split.
copy_bazel_output() {
	local target="$1" dest="$2" file count
	file="$(bazel cquery --output=files "$target" 2>/dev/null)"
	count="$(printf '%s' "$file" | grep -c .)"
	if [ "$count" -ne 1 ]; then
		echo "error: expected exactly one output file for ${target}, got ${count}:" >&2
		printf '%s\n' "$file" >&2
		return 1
	fi
	cp "$file" "$dest"
}

# Mac binaries only build on macOS hosts (require Apple C++ toolchain + cgo).
if [ "$(uname)" = "Darwin" ]; then
	copy_bazel_output //:osquery-extension-mac-amd "build/darwin/${APP_NAME}.amd64.ext"
	copy_bazel_output //:osquery-extension-mac-arm "build/darwin/${APP_NAME}.arm64.ext"
fi

copy_bazel_output //:osquery-extension-linux-amd "build/linux/${APP_NAME}.amd64.ext"
copy_bazel_output //:osquery-extension-linux-arm "build/linux/${APP_NAME}.arm64.ext"
copy_bazel_output //:osquery-extension-win-amd "build/windows/${APP_NAME}.amd64.ext.exe"

# copy_bazel_output //:osquery-extension-win-arm "build/windows/${APP_NAME}.arm64.ext.exe"
