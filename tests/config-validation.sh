#!/usr/bin/env bash
# Config validation: init must refuse malformed environment values.
#
# Every environment value is rendered into clamd.conf / freshclam.conf,
# which are plain key-space-value files. A value containing a newline
# would smuggle arbitrary extra directives into the file (config
# injection); a non-numeric port would silently render an invalid
# TCPSocket. init therefore validates every value up front and exits
# with a clear `invalid <VAR>` error before anything else runs.
#
# The image is shell-free, so the checks run from outside: the
# `--healthcheck` entrypoint path performs the same validation first,
# fails fast (no scanner is running) and never touches the network —
# `--network none` pins that. `--pull=never` keeps docker from testing
# a stale registry image instead of the local build.
#
# Usage: tests/config-validation.sh IMAGE

set -uo pipefail

IMAGE="${1:-mwaeckerlin/clamav}"

PASS=0
FAIL=0
declare -a FAILED_NAMES

_pass() { PASS=$((PASS + 1)); echo "  PASS  $1"; }
_fail() { FAIL=$((FAIL + 1)); FAILED_NAMES+=("$1"); echo "  FAIL  $1: $2"; }

_image_exists() {
    if docker image inspect "${IMAGE}" > /dev/null 2>&1; then
        return 0
    fi
    _fail "image_exists" "image not built — run 'npm run build' first"
    return 1
}

# A malformed value must abort with a message naming the variable.
_reject() {
    local name="$1" var="$2" value="$3"
    local out rc
    out=$(timeout 30 docker run --rm --pull=never --network none \
              -e "${var}=${value}" "${IMAGE}" --healthcheck 2>&1)
    rc=$?
    if [[ ${rc} -ne 0 && "${out}" == *"invalid ${var}"* ]]; then
        _pass "reject_${name}"
    else
        _fail "reject_${name}" "value not rejected (rc=${rc}): ${out}"
    fi
}

# A well-formed value must pass validation (the probe itself fails —
# no scanner is running — but no validation error may appear).
_accept() {
    local name="$1"
    shift
    local out
    out=$(timeout 30 docker run --rm --pull=never --network none \
              "$@" "${IMAGE}" --healthcheck 2>&1)
    if [[ "${out}" == *"invalid "* ]]; then
        _fail "accept_${name}" "valid value rejected: ${out}"
    else
        _pass "accept_${name}"
    fi
}

echo "==> Config validation: malformed environment must be refused"

_image_exists || { echo ""; echo "==> Config validation results: 0 passed, 1 failed"; exit 1; }

_reject port_not_numeric   CLAMD_PORT            "31x0"
_reject port_out_of_range  CLAMD_PORT            "70000"
_reject bind_injection     CLAMD_BIND            $'0.0.0.0\nTCPSocket 1234'
_reject mirror_injection   FRESHCLAM_MIRROR      $'db.example.com\nDatabaseCustomURL http://evil.example/x.cvd'
_reject filesize_bad_unit  CLAMD_MAX_FILESIZE    "2X"
_reject scansize_injection CLAMD_MAX_SCANSIZE    $'4G\nUser root'
_reject streamlen_bad      CLAMD_STREAM_MAXLENGTH "lots"
_reject checks_not_numeric FRESHCLAM_CHECKS      "hourly"
_reject checks_out_of_range FRESHCLAM_CHECKS     "99"

_accept defaults
_accept explicit_values \
    -e CLAMD_BIND=127.0.0.1 \
    -e CLAMD_PORT=3311 \
    -e CLAMD_MAX_FILESIZE=100M \
    -e CLAMD_MAX_SCANSIZE=400M \
    -e CLAMD_STREAM_MAXLENGTH=400M \
    -e FRESHCLAM_CHECKS=12 \
    -e FRESHCLAM_MIRROR=mirror.example.com

echo ""
echo "==> Config validation results: ${PASS} passed, ${FAIL} failed"
if [[ ${FAIL} -gt 0 ]]; then
    echo "==> Failed checks: ${FAILED_NAMES[*]}"
    exit 1
fi
