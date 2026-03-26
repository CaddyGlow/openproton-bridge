#!/usr/bin/env bash
# Run dovecot/imaptest against the local IMAP harness.
#
# Usage:
#   ./test-imaptest.sh                  # stress test (30s, 1 client)
#   ./test-imaptest.sh stress           # same as above
#   ./test-imaptest.sh compliance       # scripted RFC compliance tests
#   ./test-imaptest.sh benchmark        # side-by-side benchmark vs Gluon Go
#   ./test-imaptest.sh -- <extra args>  # pass arbitrary imaptest args
#
# Prerequisites:
#   - OrbStack or Docker
#   - dovecot-crlf mbox in project root (auto-downloaded if missing)
#   - cargo build (harness is built automatically)
#   - For benchmark: Go toolchain + ../gluon repo

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
GLUON_DIR="../gluon"
BENCH_SECS="${BENCH_SECS:-30}"

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

wait_for_port() {
    local port=$1 pid=$2
    for _ in $(seq 1 30); do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        sleep 0.5
    done
    return 1
}

run_imaptest() {
    "$DOCKER" run --rm --net=host \
        -v "$(pwd)/$MBOX:/tmp/dovecot-crlf:ro" \
        dovecot/imaptest \
        host=127.0.0.1 port="$PORT" \
        "$@"
}

start_rust_harness() {
    local profile="${1:-release}"
    rm -rf "$DATA_DIR" && mkdir -p "$DATA_DIR"

    if [ "$profile" = "release" ]; then
        echo "Building IMAP harness (release)..."
        OPENPROTON_CREDENTIAL_STORE=file cargo build --release --bin imap_harness 2>&1 | grep -v warning || true
        IMAP_PORT="$PORT" IMAP_DATA_DIR="$DATA_DIR" IMAP_DISABLE_RATE_LIMIT=1 RUST_LOG=warn \
            ./target/release/imap_harness >"$DATA_DIR/harness.log" 2>&1 &
    else
        echo "Building IMAP harness (debug)..."
        OPENPROTON_CREDENTIAL_STORE=file cargo build --bin imap_harness 2>&1 | grep -v warning || true
        IMAP_PORT="$PORT" IMAP_DATA_DIR="$DATA_DIR" IMAP_DISABLE_RATE_LIMIT=1 RUST_LOG=warn \
            cargo run --bin imap_harness >"$DATA_DIR/harness.log" 2>&1 &
    fi
    HARNESS_PID=$!

    if ! wait_for_port "$PORT" "$HARNESS_PID"; then
        echo "Harness failed to start. Log:"
        cat "$DATA_DIR/harness.log"
        exit 1
    fi
    echo "IMAP server ready (pid $HARNESS_PID)."
}

stop_rust_harness() {
    if [ -n "${HARNESS_PID:-}" ]; then
        kill "$HARNESS_PID" 2>/dev/null || true
        wait "$HARNESS_PID" 2>/dev/null || true
        unset HARNESS_PID
    fi
}

# Determine mode
MODE="${1:-stress}"
shift 2>/dev/null || true

case "$MODE" in
    stress)
        start_rust_harness release
        trap stop_rust_harness EXIT
        echo ""
        echo "=== imaptest stress test (${BENCH_SECS}s, 1 client) ==="
        run_imaptest \
            user="$USER" pass="$PASS" \
            mbox=/tmp/dovecot-crlf \
            clients=1 secs="$BENCH_SECS" \
            no_pipelining \
            "$@"
        ;;

    compliance)
        start_rust_harness release
        trap stop_rust_harness EXIT
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

    benchmark)
        echo "=== Benchmark: openproton-bridge vs Gluon Go (${BENCH_SECS}s each) ==="
        echo ""

        # --- Rust ---
        start_rust_harness release
        echo ""
        echo "--- openproton-bridge (Rust) ---"
        RUST_OUTPUT=$(run_imaptest \
            user="$USER" pass="$PASS" \
            mbox=/tmp/dovecot-crlf \
            clients=1 secs="$BENCH_SECS" \
            no_pipelining 2>&1)
        RUST_TOTALS=$(echo "$RUST_OUTPUT" | grep -A5 "^Totals:" | tail -1)
        RUST_LOGIN=$(echo "$RUST_TOTALS" | awk '{print $1}')
        echo "$RUST_OUTPUT" | grep -A5 "^Totals:"
        stop_rust_harness
        sleep 1

        # --- Gluon Go ---
        GLUON_LOGIN="(skipped)"
        GLUON_TOTALS=""
        if [ -d "$GLUON_DIR" ]; then
            lsof -ti :"$PORT" 2>/dev/null | xargs kill 2>/dev/null || true
            sleep 1

            echo ""
            echo "Building Gluon Go demo..."
            GLUON_BIN="/tmp/gluon-demo"
            (cd "$GLUON_DIR" && go build -o "$GLUON_BIN" ./demo/) 2>&1 | tail -3

            rm -rf /tmp/gluon-imaptest
            GLUON_DIR_DATA="/tmp/gluon-imaptest"
            GLUON_HOST="localhost:$PORT" GLUON_DIR="$GLUON_DIR_DATA" GLUON_USER_COUNT=1 GLUON_LOG_LEVEL=warn \
                "$GLUON_BIN" >/tmp/gluon-demo.log 2>&1 &
            GLUON_PID=$!

            if wait_for_port "$PORT" "$GLUON_PID"; then
                echo ""
                echo "--- Gluon Go ---"
                GLUON_OUTPUT=$(run_imaptest \
                    user=user1@example.com pass=pass \
                    mbox=/tmp/dovecot-crlf \
                    clients=1 secs="$BENCH_SECS" \
                    no_pipelining 2>&1)
                GLUON_TOTALS=$(echo "$GLUON_OUTPUT" | grep -A5 "^Totals:" | tail -1)
                GLUON_LOGIN=$(echo "$GLUON_TOTALS" | awk '{print $1}')
                echo "$GLUON_OUTPUT" | grep -A5 "^Totals:"
            else
                echo "Gluon Go failed to start."
            fi

            kill "$GLUON_PID" 2>/dev/null || true
            wait "$GLUON_PID" 2>/dev/null || true
        else
            echo ""
            echo "(Gluon Go skipped -- $GLUON_DIR not found)"
        fi

        # --- Summary ---
        echo ""
        echo "=============================="
        echo "  BENCHMARK SUMMARY (${BENCH_SECS}s)"
        echo "=============================="
        echo ""
        if [ -n "$RUST_TOTALS" ]; then
            echo "  openproton-bridge (Rust):"
            echo "    $RUST_TOTALS"
        fi
        if [ -n "$GLUON_TOTALS" ]; then
            echo ""
            echo "  Gluon Go:"
            echo "    $GLUON_TOTALS"
        fi
        echo ""
        if [ "$GLUON_LOGIN" != "(skipped)" ] && [ -n "$RUST_LOGIN" ] && [ "$RUST_LOGIN" -gt 0 ] 2>/dev/null; then
            if [ "$GLUON_LOGIN" -gt 0 ] 2>/dev/null; then
                # Calculate ratio (integer math, multiply by 100 for 2 decimal places)
                RATIO=$((RUST_LOGIN * 100 / GLUON_LOGIN))
                WHOLE=$((RATIO / 100))
                FRAC=$((RATIO % 100))
                printf "  Ratio: Rust/Go = %d.%02dx\n" "$WHOLE" "$FRAC"
                if [ "$RUST_LOGIN" -ge "$GLUON_LOGIN" ]; then
                    FASTER=$(( (RUST_LOGIN - GLUON_LOGIN) * 100 / GLUON_LOGIN ))
                    printf "  Rust is %d%% FASTER than Go\n" "$FASTER"
                else
                    SLOWER=$(( (GLUON_LOGIN - RUST_LOGIN) * 100 / GLUON_LOGIN ))
                    printf "  Rust is %d%% slower than Go\n" "$SLOWER"
                fi
            fi
        fi
        echo ""
        ;;

    --)
        start_rust_harness release
        trap stop_rust_harness EXIT
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
        echo "Usage: $0 [stress|compliance|benchmark|-- <args>]"
        echo ""
        echo "Modes:"
        echo "  stress       Run imaptest stress test (default)"
        echo "  compliance   Run scripted RFC compliance tests"
        echo "  benchmark    Side-by-side benchmark vs Gluon Go"
        echo "  -- <args>    Pass arbitrary args to imaptest"
        echo ""
        echo "Environment:"
        echo "  BENCH_SECS=30    Duration for stress/benchmark (default: 30)"
        echo "  IMAP_PORT=1143   Port to use (default: 1143)"
        exit 1
        ;;
esac
