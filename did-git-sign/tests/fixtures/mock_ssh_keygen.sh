#!/usr/bin/env sh
# Mock ssh-keygen for did-git-sign unit tests.
#
# Writes each received argument on its own line to the file path stored in
# DID_GIT_SIGN_TEST_MOCK_OUT.  The test reads that file and asserts that the
# expected flags are present, allowing delegate_to_ssh_keygen to be tested
# without invoking the real ssh-keygen binary.
set -eu

# Guard: if the env var is unset or empty the script must fail loudly so the
# test framework sees a non-zero exit rather than silently producing no output.
if [ -z "${DID_GIT_SIGN_TEST_MOCK_OUT:-}" ]; then
    echo "mock_ssh_keygen: DID_GIT_SIGN_TEST_MOCK_OUT is not set" >&2
    exit 1
fi

printf '%s\n' "$@" > "$DID_GIT_SIGN_TEST_MOCK_OUT"
exit 0
