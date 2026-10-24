#!/usr/bin/env sh
# Runs a command under pcsc-spy and prints only its call statistics; the APDUs, which carry the
# holder's data, go nowhere. Linux with pcsc-lite 2 only.
set -eu

delegate=$(dirname "$(ldconfig -p | sed -n 's/.*libpcsclite_real.so.1.*=> //p' | head -n 1)")/libpcscspy.so.0
fifo="$HOME/pcsc-spy"
[ -p "$fifo" ] || mkfifo "$fifo"

pcsc-spy --nocolor "$fifo" | sed -n '/^Thread/,$p' &
spy=$!
status=0
LIBPCSCLITE_DELEGATE="$delegate" "$@" || status=$?
wait "$spy"
exit "$status"
