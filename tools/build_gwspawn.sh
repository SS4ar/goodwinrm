#!/bin/sh
set -eu

cd "$(dirname "$0")"

CFLAGS="-municode -Os -static -s -DUNICODE -D_UNICODE"
LIBS="-lole32 -loleaut32 -lwbemuuid -luuid -ladvapi32"

x86_64-w64-mingw32-gcc $CFLAGS -o gwspawn_x64.exe gwspawn.c $LIBS
base64 -w 0 gwspawn_x64.exe
echo

if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    i686-w64-mingw32-gcc $CFLAGS -o gwspawn_x86.exe gwspawn.c $LIBS
    base64 -w 0 gwspawn_x86.exe
    echo
fi
