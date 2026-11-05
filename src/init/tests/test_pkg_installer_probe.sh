#!/bin/bash

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives the manager probes of pkg_installer.sh: probe_server() with its TCP fallback,
# probe_server_verified() and probe_server_with_ca(). They are cut out of the real script and
# sourced together with probe_build_target() and probe_curl(). A stub curl models the two hosts
# whose curl rejects --tlsv1.3 (exit 4):
#
#   Amazon Linux 2        the same handshake without the option fails with 35 (the default model)
#   macOS                 the same handshake without the option succeeds, because the manager
#                         accepts nothing below TLS 1.3
#
# STUB_TLS13_RC, STUB_RETRY_RC and STUB_K_RC set what the stub answers, so each case picks its
# model. A local listener stands in for the manager.
#
#   ./test_pkg_installer_probe.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../pkg_installer.sh"

failures=0
checks=0

WORK="$(mktemp -d)"
LISTENER_PID=""
trap '[ -n "${LISTENER_PID}" ] && kill "${LISTENER_PID}" 2>/dev/null; rm -rf "${WORK}"' EXIT

check() {

    local name="$1" expected="$2" actual="$3"

    checks=$(( checks + 1 ))
    if [ "${expected}" = "${actual}" ]; then
        echo "ok   - ${name}"
    else
        failures=$(( failures + 1 ))
        echo "FAIL - ${name}"
        echo "--- expected ---"
        echo "${expected}"
        echo "--- actual ---"
        echo "${actual}"
        echo "---"
    fi

}

sed -n '/^probe_build_target() {/,/^}/p;/^probe_curl() {/,/^}/p;/^probe_server() {/,/^}/p;/^probe_server_verified() {/,/^}/p;/^probe_server_with_ca() {/,/^}/p' "${TARGET}" > "${WORK}/probe.sh"

# With --tlsv1.3 the stub exits STUB_TLS13_RC (default 4, option rejected). Without it, STUB_RETRY_RC
# (default 35), or STUB_K_RC when the call also carries -k.
mkdir -p "${WORK}/bin" "${WORK}/logs"
cat > "${WORK}/bin/curl" <<'STUB'
#!/bin/sh
tls13=0
k=0
for arg in "$@"; do
    [ "${arg}" = "--tlsv1.3" ] && tls13=1
    [ "${arg}" = "-k" ] && k=1
done
[ ${tls13} -eq 1 ] && exit "${STUB_TLS13_RC:-4}"
[ ${k} -eq 1 ] && [ -n "${STUB_K_RC}" ] && exit "${STUB_K_RC}"
exit "${STUB_RETRY_RC:-35}"
STUB
chmod +x "${WORK}/bin/curl"

python3 -c 'import socket, sys
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(16)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept(); c.close()' > "${WORK}/port" &
LISTENER_PID=$!
disown "${LISTENER_PID}"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "${WORK}/port" ] && break
    sleep 0.2
done
PORT="$(cat "${WORK}/port")"

# A port nothing listens on: bind one, then close it.
CLOSED_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"

# $1 = function, $2 = host, $3 = port, $4 = shell code run before the probe, in the same shell.
# Prints the function's exit code.
run_probe() {
    ( cd "${WORK}" && PATH="${WORK}/bin:${PATH}" bash -c ". ./probe.sh; $4
      $1 \"\$0\" \"\$1\" wazuh-manager ${WORK}/ca.pem; echo \$?" "$2" "$3" 2>/dev/null )
}

# $1 = host, $2 = port, $3 = shell code run before the probe, in the same shell.
probe() {
    run_probe probe_server "$1" "$2" "$3"
}

# Empty the log, run the function and print "<exit code> <log lines matching the pattern>".
# $1 = function, $2 = shell code run before the probe, $3 = host, $4 = log pattern.
probe_and_log() {
    local rc
    : > "${WORK}/logs/upgrade.log"
    rc="$(run_probe "$1" "$3" "${PORT}" "$2")"
    echo "${rc} $(grep -c "$4" "${WORK}/logs/upgrade.log"; true)"
}

check "the fallback does not redirect onto a fixed fd" "" \
    "$(sed -n '/^probe_server() {/,/^}/p' "${TARGET}" | grep -E '[0-9]+<>[^&]*/dev/tcp')"

check "a reachable manager passes" "0" "$(probe 127.0.0.1 "${PORT}")"
check "the fallback is logged" "1" \
    "$(grep -c 'falling back to a TCP connectivity check' "${WORK}/logs/upgrade.log")"
check "a reachable manager named by host name passes" "0" "$(probe localhost "${PORT}")"
check "a reachable manager passes with fd 3 closed" "0" "$(probe localhost "${PORT}" 'exec 3<&-')"
check "a reachable manager passes with fd 3 already open" "0" \
    "$(probe localhost "${PORT}" 'exec 3</dev/null')"
check "a closed port fails" "1" "$(probe 127.0.0.1 "${CLOSED_PORT}")"
check "a name that does not resolve fails" "1" "$(probe no-such-host.invalid "${PORT}")"

# probe_server() with a curl that does TLS 1.3 once --tlsv1.3 is dropped (macOS).
FALLBACK='falling back to a TCP connectivity check'
MACOS_PASS='export STUB_RETRY_RC=0'
check "macOS: the retry succeeds, so the manager passes with no fallback" "0 0" \
    "$(probe_and_log probe_server "${MACOS_PASS}" 127.0.0.1 "${FALLBACK}")"
check "macOS: a wrong prefix (22 on the retry) fails with no fallback" "22 0" \
    "$(probe_and_log probe_server 'export STUB_RETRY_RC=22' 127.0.0.1 "${FALLBACK}")"
check "macOS: a closed port (7 on the retry) fails with no fallback" "7 0" \
    "$(probe_and_log probe_server 'export STUB_RETRY_RC=7' 127.0.0.1 "${FALLBACK}")"
# probe_server() with a curl that takes --tlsv1.3 (no retry).
check "a curl with TLS 1.3 passes with no fallback" "0 0" \
    "$(probe_and_log probe_server 'export STUB_TLS13_RC=0' 127.0.0.1 "${FALLBACK}")"
check "a handshake failure (35) without a retry fails and does not fall back" "35 0" \
    "$(probe_and_log probe_server 'export STUB_TLS13_RC=35' 127.0.0.1 "${FALLBACK}")"
check "AL2: 35 on the retry falls back to TCP and passes" "0 1" \
    "$(probe_and_log probe_server '' 127.0.0.1 "${FALLBACK}")"
check "a curl that does not know --tlsv1.3 at all (exit 2) retries the same way" "0 0" \
    "$(probe_and_log probe_server 'export STUB_TLS13_RC=2 STUB_RETRY_RC=0' 127.0.0.1 "${FALLBACK}")"
check "macOS: a timeout (28 on the retry) fails with no fallback" "28 0" \
    "$(probe_and_log probe_server 'export STUB_RETRY_RC=28' 127.0.0.1 "${FALLBACK}")"

# probe_server_verified() and probe_server_with_ca(). The log pattern is the line saying this
# host's curl cannot do TLS 1.3.
NO_TLS13="This host's curl cannot negotiate TLS 1.3"
check "verified, macOS: the retry succeeds" "0 0" \
    "$(probe_and_log probe_server_verified "${MACOS_PASS}" 127.0.0.1 "${NO_TLS13}")"
check "verified, macOS: an untrusted certificate (60 on the retry) is not logged as no TLS 1.3" "60 0" \
    "$(probe_and_log probe_server_verified 'export STUB_RETRY_RC=60' 127.0.0.1 "${NO_TLS13}")"
check "verified, AL2: 35 on the retry is logged as no TLS 1.3 and stays fail-closed" "35 1" \
    "$(probe_and_log probe_server_verified '' 127.0.0.1 "${NO_TLS13}")"
check "verified: 35 from a curl that takes --tlsv1.3 is not logged as no TLS 1.3" "35 0" \
    "$(probe_and_log probe_server_verified 'export STUB_TLS13_RC=35' 127.0.0.1 "${NO_TLS13}")"

check "with CA, macOS: the CA verifies (0 on the retry)" "0 0" \
    "$(probe_and_log probe_server_with_ca "${MACOS_PASS}" 127.0.0.1 "${NO_TLS13}")"
check "with CA, macOS: the CA verifies (22 on the retry)" "0 0" \
    "$(probe_and_log probe_server_with_ca 'export STUB_RETRY_RC=22' 127.0.0.1 "${NO_TLS13}")"
check "with CA, macOS: the CA does not verify (60 on the retry)" "1 0" \
    "$(probe_and_log probe_server_with_ca 'export STUB_RETRY_RC=60' 127.0.0.1 "${NO_TLS13}")"
check "with CA, macOS: 35 that succeeds with -k is a CA that does not verify" "1 0" \
    "$(probe_and_log probe_server_with_ca 'export STUB_RETRY_RC=35 STUB_K_RC=0' 127.0.0.1 "${NO_TLS13}")"
check "with CA, macOS: no answer (7 on the retry) could not tell" "2 0" \
    "$(probe_and_log probe_server_with_ca 'export STUB_RETRY_RC=7' 127.0.0.1 "${NO_TLS13}")"
check "with CA, AL2: 35 on the retry could not tell" "2 0" \
    "$(probe_and_log probe_server_with_ca '' 127.0.0.1 "${NO_TLS13}")"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
