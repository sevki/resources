#!/bin/bash
#
# Screenshot tests: starts an installed Resources inside a private Xvfb with
# fixed fonts, theme, window size and settings, takes screenshots of
# deterministic parts of the UI and compares them against the golden images
# in tests/screenshots/golden.
#
# Usage:
#   tests/screenshots/run.sh --prefix <install prefix> [--update] [--out <dir>]
#
#   --prefix   prefix Resources was installed to (meson -Dprefix=…; ninja install)
#   --update   overwrite the golden images with the current screenshots
#   --out      where to put the screenshots (default: ./screenshots-out)
#
# Requires: Xvfb, xdotool, ImageMagick (import, convert, compare), dbus-run-session.
# Screenshots of live data (process list, graphs, sidebar) are deliberately
# not part of the comparison as they can't be reproduced.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
golden="$here/golden"
out="$PWD/screenshots-out"
prefix=""
update=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) prefix="$(realpath "$2")"; shift 2 ;;
        --update) update=1; shift ;;
        --out) out="$(realpath -m "$2")"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -x "$prefix/bin/resources" ]] || { echo "no $prefix/bin/resources, pass --prefix" >&2; exit 2; }

# percentage of pixels allowed to differ (font rasterization noise)
tolerance_percent="0.15"

mkdir -p "$out"
work="$(mktemp -d)"
display=":$((100 + RANDOM % 800))"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$work"
}
trap cleanup EXIT

# --- deterministic environment ------------------------------------------
export XDG_CONFIG_HOME="$work/config"
export XDG_DATA_DIRS="$prefix/share:/usr/share"
export GSETTINGS_SCHEMA_DIR="$prefix/share/glib-2.0/schemas"
export GSETTINGS_BACKEND=keyfile
export GDK_BACKEND=x11 GSK_RENDERER=cairo GTK_A11Y=none LC_ALL=C.UTF-8 LANGUAGE=C
export DISPLAY="$display"
unset GTK_THEME

mkdir -p "$XDG_CONFIG_HOME/gtk-4.0" "$XDG_CONFIG_HOME/glib-2.0/settings"
cat > "$XDG_CONFIG_HOME/gtk-4.0/settings.ini" <<INI
[Settings]
gtk-font-name=DejaVu Sans 10
gtk-icon-theme-name=Adwaita
gtk-enable-animations=false
gtk-cursor-blink=false
gtk-xft-antialias=1
gtk-xft-hinting=0
gtk-xft-hintstyle=hintnone
gtk-xft-rgba=none
gtk-xft-dpi=98304
gtk-application-prefer-dark-theme=false
INI
cat > "$XDG_CONFIG_HOME/glib-2.0/settings/keyfile" <<INI
[org/gnome/Resources]
window-width=1020
window-height=860
is-maximized=false
last-viewed-page='processes'
INI

Xvfb "$display" -screen 0 1280x900x24 -nolisten tcp >/dev/null 2>&1 &
pids+=($!)
for _ in $(seq 50); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.2; done

dbus-run-session -- "$prefix/bin/resources" >"$out/resources.log" 2>&1 &
pids+=($!)
sleep 8

key()   { xdotool key --clearmodifiers "$@"; sleep 1.2; }
click() { xdotool mousemove "$1" "$2" click 1; sleep 1.2; }
park()  { xdotool mousemove 1270 890; sleep 0.8; }

# shoot <name> <WxH+X+Y>: screenshot of a region of the screen
shoot() {
    park
    import -window root "$out/$1.full.png"
    convert "$out/$1.full.png" -crop "$2" +repage "$out/$1.png"
}

# --- scenarios -------------------------------------------------------------
# Coordinates refer to the fixed 1020x860 window at the top left of the screen.

click 640 28   # focus the window by clicking its (inert) title

# header bar of the Processes page
shoot processes-header 360x48+258+4

# main menu
click 235 28
shoot main-menu 140x94+165+66
key Escape

# preferences, Processes tab
key ctrl+comma
click 573 78
shoot preferences-processes 600x720+210+70
key Escape

# --- compare ---------------------------------------------------------------
status=0
for shot in processes-header main-menu preferences-processes; do
    if [[ $update == 1 ]]; then
        cp "$out/$shot.png" "$golden/$shot.png"
        echo "updated $shot"
        continue
    fi
    if [[ ! -f "$golden/$shot.png" ]]; then
        echo "FAIL $shot: no golden image" >&2; status=1; continue
    fi
    total=$(identify -format '%[fx:w*h]' "$out/$shot.png")
    different=$(compare -metric AE -fuzz 6% "$out/$shot.png" "$golden/$shot.png" "$out/$shot.diff.png" 2>&1 || true)
    different="${different%% *}"
    limit=$(awk -v t="$total" -v p="$tolerance_percent" 'BEGIN { printf "%d", t * p / 100 }')
    if [[ "$different" =~ ^[0-9]+$ ]] && (( different <= limit )); then
        echo "ok   $shot ($different of $total pixels differ, limit $limit)"
    else
        echo "FAIL $shot ($different of $total pixels differ, limit $limit) — see $out/$shot.diff.png" >&2
        status=1
    fi
done
exit $status
