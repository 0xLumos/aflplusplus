#!/bin/bash
# =============================================================================
# AFL++ GOD TIER SWARM LAUNCHER — 1 Master + 7 Slaves
# Based on: AFL++ best practices + Chromium Mojo sandbox harness
# Roles: master=ASAN+CmpLog | slaves=fast/rare/havoc/mopt splits
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — PATHS  (edit these before running)
# ─────────────────────────────────────────────────────────────────────────────
WORKDIR="$HOME/SurgicalFuzz"
SRC="$WORKDIR/chromium/src"

# Harness binaries (build these before running this script)
HARNESS_ASAN="$SRC/out/fuzz/mojo_parse_messages_fuzzer"       # ASan+instrumented
HARNESS_FAST="$SRC/out/fuzz_fast/mojo_parse_messages_fuzzer"  # instrumented only, no sanitizers
HARNESS_CMPLOG="$SRC/out/fuzz_cmplog/mojo_parse_messages_fuzzer" # CmpLog build (-fsanitize-coverage=trace-cmp)

SEEDS="$WORKDIR/seeds"          # starting corpus
OUT="$WORKDIR/out_fuzz"         # AFL++ output dir (all instances sync here)
DICT="$WORKDIR/mojo.dict"       # optional dictionary (created below if missing)
LOGS="$WORKDIR/logs"            # per-instance stdout logs for post-mortem

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — ENVIRONMENT FLAGS
# Article: AFL_AUTORESUME, AFL_NO_TRIM, ASAN_OPTIONS are essential
# ─────────────────────────────────────────────────────────────────────────────
BASE_ENV="
export AFL_AUTORESUME=1;
export AFL_NO_TRIM=1;
export AFL_IMPORT_FIRST=1;
export AFL_FORCE_UI=1;
export AFL_TMPDIR=/tmp;
export ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:symbolize=0';
export UBSAN_OPTIONS='halt_on_error=1:abort_on_error=1:print_stacktrace=0';
"
# AFL_AUTORESUME=1  → safe to kill/restart without losing corpus
# AFL_NO_TRIM=1     → skip trim phase on fresh runs (enable after 24h)
# AFL_IMPORT_FIRST=1 → slaves pull master corpus before starting own mutations
# AFL_FORCE_UI=1    → keep the ncurses UI inside screen sessions
# ASAN detect_leaks=0 → ignore leaks (flood false positives when fuzzing)
# ASAN abort_on_error=1 → hard crash on real bugs so AFL++ catches them
# ASAN symbolize=0  → skip symbolization during fuzzing (use =1 for repro only)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — PREFLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════"
echo "  AFL++ SWARM PREFLIGHT"
echo "════════════════════════════════════════════════════════"

# Check AFL++ is installed
if ! command -v afl-fuzz &>/dev/null; then
    echo "[FATAL] afl-fuzz not found in PATH. Install AFL++ first."
    exit 1
fi
AFL_VER=$(afl-fuzz --version 2>&1 | head -1)
echo "[OK] $AFL_VER"

# Check harnesses exist
for BIN in "$HARNESS_ASAN" "$HARNESS_FAST" "$HARNESS_CMPLOG"; do
    if [[ ! -x "$BIN" ]]; then
        echo "[WARN] Missing or non-executable: $BIN"
        echo "       → Falling back to ASAN binary for all roles."
        HARNESS_FAST="$HARNESS_ASAN"
        HARNESS_CMPLOG="$HARNESS_ASAN"
        break
    fi
done

# Check seeds exist and are non-empty
if [[ ! -d "$SEEDS" ]] || [[ -z "$(ls -A "$SEEDS")" ]]; then
    echo "[INFO] No seeds found — generating minimal Mojo corpus..."
    mkdir -p "$SEEDS"
    # Mojo message header: 16-byte fixed header + empty payload
    # Format: [data_num_bytes(4)] [version+flags(2)] [name(4)] [request_id(8)]
    printf '\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        > "$SEEDS/mojo_empty.bin"
    printf '\x10\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00' \
        > "$SEEDS/mojo_req.bin"
    printf '\x10\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x00\x00\x00' \
        > "$SEEDS/mojo_resp.bin"
    printf '\x18\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        > "$SEEDS/mojo_large.bin"
    echo "[OK] Minimal Mojo seeds written to $SEEDS"
fi
echo "[OK] Seeds: $(ls "$SEEDS" | wc -l) files"

# Generate a Mojo IPC dictionary if missing
if [[ ! -f "$DICT" ]]; then
    echo "[INFO] Generating Mojo IPC dictionary..."
    cat > "$DICT" << 'DICT_EOF'
# Mojo message magic bytes and common IPC tokens
mojo_hdr="\x10\x00\x00\x00"
version_0="\x00\x00"
version_1="\x01\x00"
flag_wants_reply="\x01\x00"
flag_is_reply="\x02\x00"
flag_no_error="\x00\x00"
handles_present="\x01\x00\x00\x00"
no_handles="\x00\x00\x00\x00"
msg_type_request="\x01\x00\x00\x00"
msg_type_response="\x02\x00\x00\x00"
msg_type_event="\x03\x00\x00\x00"
assoc_req="\x04\x00\x00\x00"
pipe_create="\x05\x00\x00\x00"
max_uint32="\xFF\xFF\xFF\xFF"
zero_id="\x00\x00\x00\x00"
DICT_EOF
    echo "[OK] Dictionary created at $DICT"
fi

# System tuning check
CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "unknown")
if [[ "$CORE_PATTERN" == "core" ]] || [[ "$CORE_PATTERN" == "unknown" ]]; then
    echo "[OK] Core pattern is clean."
else
    echo "[WARN] core_pattern=$CORE_PATTERN — AFL++ may complain. Fix with:"
    echo "       echo core | sudo tee /proc/sys/kernel/core_pattern"
fi

SCALE=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "skip")
if [[ "$SCALE" != "performance" ]] && [[ "$SCALE" != "skip" ]]; then
    echo "[WARN] CPU governor is '$SCALE' — set to 'performance' for max speed:"
    echo "       echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — PREP DIRECTORIES & KILL STALE SCREENS
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p "$OUT" "$LOGS"

echo ""
echo "[*] Killing any stale swarm screens..."
screen -ls 2>/dev/null \
    | grep -E '\.(master|slave[0-9]+|monitor)' \
    | awk -F'.' '{print $1}' \
    | xargs -r -I{} screen -X -S {} quit 2>/dev/null || true
sleep 1

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — MASTER (ASan + CmpLog + Dictionary + -D deterministic)
# Role: heavy lifting, syncing, cmplog magic-byte solving, ASAN crash detection
# Article: "master=ASAN+CmpLog, -c for cmplog, -D for deterministic, -l 2"
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Spawning MASTER (ASAN + CmpLog + dict + deterministic)..."
screen -dmS master bash -c "
    $BASE_ENV
    /usr/local/bin/afl-fuzz \
        -i '$SEEDS' \
        -o '$OUT' \
        -M master \
        -c '$HARNESS_CMPLOG' \
        -l 2 \
        -D \
        -m none \
        -t 10000+ \
        -x '$DICT' \
        -- '$HARNESS_ASAN' @@ \
    2>&1 | tee '$LOGS/master.log'
"
# -M master     → designates master, enables inter-instance syncing
# -c cmplog     → RedQueen: solves magic bytes/checksums by injection
# -l 2          → CmpLog intensity level 2 (balanced)
# -D            → enable deterministic mutations (slow but thorough)
# -m none       → no memory limit (required for ASAN builds)
# -t 10000+     → 10s timeout, + means AFL++ auto-adjusts upward if needed
# -x dict       → feed IPC keywords into mutation engine
echo "[OK] Master spawned → screen -r master"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — SLAVE 1 & 2: FAST (pure speed, no sanitizers, havoc-heavy)
# Role: rip through corpus at max exec/s, generate new paths for master to triage
# Article: "fast slaves: no sanitizers, just instrumentation, -z havoc only"
# ─────────────────────────────────────────────────────────────────────────────
for i in 1 2; do
    echo "[*] Spawning SLAVE $i (FAST / havoc / max throughput)..."
    screen -dmS "slave${i}" bash -c "
        $BASE_ENV
        /usr/local/bin/afl-fuzz \
            -i '$SEEDS' \
            -o '$OUT' \
            -S 'slave${i}' \
            -z \
            -p fast \
            -m none \
            -t 2000 \
            -x '$DICT' \
            -- '$HARNESS_FAST' @@ \
        2>&1 | tee '$LOGS/slave${i}.log'
    "
    # -z → havoc-only mode (no deterministic, pure mutation speed)
    # -p fast → power schedule: prioritize fast-to-execute corpus entries
done
echo "[OK] Slaves 1-2 spawned (FAST)"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — SLAVE 3 & 4: RARE (target under-covered code paths)
# Role: find edges that fast slaves miss by prioritizing rarely-hit paths
# Article: "-p rare will focus on corpus files that cause code reached least"
# ─────────────────────────────────────────────────────────────────────────────
for i in 3 4; do
    echo "[*] Spawning SLAVE $i (RARE power schedule — low-coverage paths)..."
    screen -dmS "slave${i}" bash -c "
        $BASE_ENV
        /usr/local/bin/afl-fuzz \
            -i '$SEEDS' \
            -o '$OUT' \
            -S 'slave${i}' \
            -z \
            -p rare \
            -m none \
            -t 2000 \
            -x '$DICT' \
            -- '$HARNESS_FAST' @@ \
        2>&1 | tee '$LOGS/slave${i}.log'
    "
    # -p rare → power schedule: focus on the least-hit edges in the bitmap
done
echo "[OK] Slaves 3-4 spawned (RARE)"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — SLAVE 5: MOpt (smash corpus pairs, radical mutation)
# Role: combine two good corpus files → find paths neither alone would reach
# Article: "-L 0 enables MOpt/M0pt mode, smashes existing corpus together"
# ─────────────────────────────────────────────────────────────────────────────
echo "[*] Spawning SLAVE 5 (MOpt — corpus smasher)..."
screen -dmS "slave5" bash -c "
    $BASE_ENV
    /usr/local/bin/afl-fuzz \
        -i '$SEEDS' \
        -o '$OUT' \
        -S 'slave5' \
        -L 0 \
        -m none \
        -t 2000 \
        -x '$DICT' \
        -- '$HARNESS_FAST' @@ \
    2>&1 | tee '$LOGS/slave5.log'
"
# -L 0 → MOpt mode: uses particle swarm optimization to mutate, learns which
#         mutation operators are working and upweights them over time
echo "[OK] Slave 5 spawned (MOpt)"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — SLAVE 6: ASAN (second ASAN instance, -p explore)
# Role: catch memory bugs that the fast slaves would miss (no sanitizers)
# Article: "ASan instance detects memory corruption: UAF, double-free, overflows"
# ─────────────────────────────────────────────────────────────────────────────
echo "[*] Spawning SLAVE 6 (ASAN / explore — memory bug detection)..."
screen -dmS "slave6" bash -c "
    $BASE_ENV
    /usr/local/bin/afl-fuzz \
        -i '$SEEDS' \
        -o '$OUT' \
        -S 'slave6' \
        -p explore \
        -m none \
        -t 5000 \
        -x '$DICT' \
        -- '$HARNESS_ASAN' @@ \
    2>&1 | tee '$LOGS/slave6.log'
"
# -p explore → power schedule: broadens coverage, good paired with ASAN
# Higher -t since ASAN adds ~2x overhead per exec
echo "[OK] Slave 6 spawned (ASAN + explore)"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10 — SLAVE 7: CRASH EXPLORER (-C Were-Rabbit mode)
# Role: if crashes already exist from prior runs, hammer them for variant paths
# Article: "-C Peruvian Were-Rabbit: finds all code paths leading to a crash"
# Note: only activates if prior crashes exist, otherwise runs as a fast slave
# ─────────────────────────────────────────────────────────────────────────────
echo "[*] Spawning SLAVE 7 (Were-Rabbit crash explorer / fallback fast)..."
CRASH_CORPUS="$OUT/master/crashes"
if [[ -d "$CRASH_CORPUS" ]] && [[ -n "$(ls -A "$CRASH_CORPUS" 2>/dev/null)" ]]; then
    screen -dmS "slave7" bash -c "
        $BASE_ENV
        /usr/local/bin/afl-fuzz \
            -i '$CRASH_CORPUS' \
            -o '${OUT}_rabbit' \
            -S 'slave7' \
            -C \
            -m none \
            -t 5000 \
            -- '$HARNESS_ASAN' @@ \
        2>&1 | tee '$LOGS/slave7.log'
    "
    echo "[OK] Slave 7 spawned (Were-Rabbit — existing crashes found)"
else
    # No crashes yet — run as a second MOpt instance to maximize early coverage
    screen -dmS "slave7" bash -c "
        $BASE_ENV
        /usr/local/bin/afl-fuzz \
            -i '$SEEDS' \
            -o '$OUT' \
            -S 'slave7' \
            -L 0 \
            -p rare \
            -m none \
            -t 2000 \
            -x '$DICT' \
            -- '$HARNESS_FAST' @@ \
        2>&1 | tee '$LOGS/slave7.log'
    "
    echo "[OK] Slave 7 spawned (MOpt+rare — no crashes yet, will auto-switch)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 11 — MONITOR SCREEN
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Spawning global monitor..."
screen -dmS monitor bash -c "
    watch -n 2 -c 'afl-whatsup -s -d $OUT'
"
echo "[OK] Monitor spawned → screen -r monitor"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 12 — STATUS SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  SWARM LIVE — $(date)"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  ROLE          SCREEN         FLAGS"
echo "  ──────────────────────────────────────────────────────"
echo "  Master        screen -r master    ASAN + CmpLog + -D + dict"
echo "  Slave 1       screen -r slave1    FAST havoc -p fast"
echo "  Slave 2       screen -r slave2    FAST havoc -p fast"
echo "  Slave 3       screen -r slave3    FAST havoc -p rare"
echo "  Slave 4       screen -r slave4    FAST havoc -p rare"
echo "  Slave 5       screen -r slave5    MOpt  (-L 0)"
echo "  Slave 6       screen -r slave6    ASAN  -p explore"
echo "  Slave 7       screen -r slave7    Were-Rabbit / MOpt+rare"
echo "  Monitor       screen -r monitor   afl-whatsup -s -d $OUT"
echo ""
echo "  Output dir:   $OUT"
echo "  Logs dir:     $LOGS"
echo "  Seeds used:   $SEEDS"
echo ""
echo "  KEY METRICS TO WATCH (in monitor):"
echo "  • Fuzzers Alive    — all 8 should show up"
echo "  • Pending Favs     — should drain over time (means progress)"
echo "  • Coverage         — should climb in first few hours"
echo "  • Crashes Saved    — your victories"
echo "  • Time w/o finds   — if >24h, reconsider harness or seeds"
echo ""
echo "  TIPS:"
echo "  • After ~24h: remove AFL_NO_TRIM=1 to start trimming corpus"
echo "  • When first crash found: re-run slave7 — it will auto-switch to -C mode"
echo "  • To reproduce a crash: ASAN_OPTIONS='symbolize=1' ./harness_asan <crash_file>"
echo "  • Check disk: df -h $WORKDIR"
echo "════════════════════════════════════════════════════════"
