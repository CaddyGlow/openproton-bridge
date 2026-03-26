#!/usr/bin/env bash
# Run dovecot/imaptest against the local IMAP harness.
#
# Usage:
#   ./test-imaptest.sh                  # stress test (30s, 1 client)
#   ./test-imaptest.sh compliance       # scripted RFC compliance tests
#   ./test-imaptest.sh stress           # stress test with checkpoint
#   ./test-imaptest.sh -- <extra args>  # pass arbitrary imaptest args
#
# Prerequisites:
#   - OrbStack or Docker
#   - dovecot-crlf mbox in project root (auto-downloaded if missing)
#   - cargo build (harness is built automatically)

set -euo pipefail
cd "$(dirname "$0")"

DOCKER="/Applications/OrbStack.app/Contents/MacOS/xbin/docker"
if ! command -v "$DOCKER" &>/dev/null; then
    DOCKER="docker"
fi

PORT="${IMAP_PORT:-1143}"
USER="testuser@localhost"
PASS="testpass"
MBOX="dovecot-crlf"
DATA_DIR="${TMPDIR:-/tmp}/openproton-imaptest"

# Download test mbox if missing
if [ ! -f "$MBOX" ]; then
    echo "Downloading dovecot test mbox..."
    curl -Lo "$MBOX" https://www.dovecot.org/tmp/dovecot-crlf
fi

# Clone imaptest repo for scripted tests if not present
IMAPTEST_REPO="/tmp/imaptest-repo"
if [ ! -d "$IMAPTEST_REPO/src/tests" ]; then
    echo "Cloning imaptest repo for scripted tests..."
    git clone --depth 1 https://github.com/dovecot/imaptest.git "$IMAPTEST_REPO"
fi

# Build harness
echo "Building IMAP harness..."
OPENPROTON_CREDENTIAL_STORE=file cargo build --bin imap_harness 2>&1 | grep -v warning || true

# Clean up previous harness data and start fresh
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

# Start IMAP harness in background
echo "Starting IMAP harness on port $PORT..."
IMAP_PORT="$PORT" IMAP_DATA_DIR="$DATA_DIR" IMAP_DISABLE_RATE_LIMIT=1 RUST_LOG=warn \
    cargo run --bin imap_harness >"$DATA_DIR/harness.log" 2>&1 &
HARNESS_PID=$!

cleanup() {
    echo ""
    echo "Stopping IMAP harness (pid $HARNESS_PID)..."
    kill "$HARNESS_PID" 2>/dev/null || true
    wait "$HARNESS_PID" 2>/dev/null || true
    echo "Harness log: $DATA_DIR/harness.log"
}
trap cleanup EXIT

# Wait for the server to be ready
echo "Waiting for IMAP server..."
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
        echo "IMAP server ready."
        break
    fi
    if ! kill -0 "$HARNESS_PID" 2>/dev/null; then
        echo "Harness exited unexpectedly. Log:"
        cat "$DATA_DIR/harness.log"
        exit 1
    fi
    sleep 0.5
done

if ! nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    echo "Timed out waiting for IMAP server. Log:"
    cat "$DATA_DIR/harness.log"
    exit 1
fi

# Determine mode
MODE="${1:-stress}"
shift 2>/dev/null || true

case "$MODE" in
    stress)
        echo ""
        echo "=== imaptest stress test (30s, 1 client) ==="
        "$DOCKER" run --rm --net=host \
            -v "$(pwd)/$MBOX:/tmp/dovecot-crlf:ro" \
            dovecot/imaptest \
            host=127.0.0.1 port="$PORT" \
            user="$USER" pass="$PASS" \
            mbox=/tmp/dovecot-crlf \
            clients=1 secs=30 \
            no_pipelining \
            "$@"
        ;;
    compliance)
        echo ""
        echo "=== imaptest scripted compliance tests ==="
        "$DOCKER" run --rm --net=host \
            -v "$(pwd)/$MBOX:/tmp/dovecot-crlf:ro" \
            -v "$IMAPTEST_REPO/src/tests:/tests:ro" \
            dovecot/imaptest \
            host=127.0.0.1 port="$PORT" \
            user="$USER" pass="$PASS" \
            mbox=/tmp/dovecot-crlf \
            test=/tests \
            "$@"
        ;;
    --)
        echo ""
        echo "=== imaptest custom args ==="
        "$DOCKER" run --rm --net=host \
            -v "$(pwd)/$MBOX:/tmp/dovecot-crlf:ro" \
            -v "$IMAPTEST_REPO/src/tests:/tests:ro" \
            dovecot/imaptest \
            host=127.0.0.1 port="$PORT" \
            user="$USER" pass="$PASS" \
            mbox=/tmp/dovecot-crlf \
            "$@"
        ;;
    *)
        echo "Usage: $0 [stress|compliance|-- <args>]"
        exit 1
        ;;
esac
