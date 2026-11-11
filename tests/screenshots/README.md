# Screenshot tests

`run.sh` starts an installed Resources in a private Xvfb with a pinned font
(DejaVu Sans), icon theme, window size and settings, takes screenshots of the
parts of the UI that don't show live data, and compares them to the images in
`golden/` (a small number of differing pixels is tolerated).

Covered: header bar of the Processes page, main menu, Preferences → Processes,
and the Find dialog. The process list, graphs and sidebar are deliberately not
compared because their content changes all the time.

```sh
# build and install somewhere (dev profile)
meson setup build -Dprofile=dev -Dprefix="$PWD/install"
ninja -C build install

tests/screenshots/run.sh --prefix "$PWD/install"            # compare
tests/screenshots/run.sh --prefix "$PWD/install" --update   # accept changes
```

Needs `Xvfb`, `xdotool`, ImageMagick and `dbus-run-session`. On failure
`screenshots-out/<name>.diff.png` shows what differs. CI uploads the
screenshots of every run as the `screenshots` artifact, so goldens can also be
refreshed from there. After intentional UI changes, run with `--update` and
commit the new images.

Goldens are rendered with the libadwaita 1.5 of Ubuntu 24.04 (see
`build-aux/ci-compat-libadwaita.sh`); a different libadwaita or font setup will
render slightly differently.
