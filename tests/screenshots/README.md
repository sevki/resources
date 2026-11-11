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
`screenshots-out/<name>.diff.png` shows what differs.

## Updating the golden images

Text is rasterized slightly differently on different machines (same layout,
different glyph edges), so the goldens are the images rendered **by the CI
runner**. After an intentional UI change, push it, let the `screenshots` job
fail, and run

```sh
tests/screenshots/update-from-ci.sh <workflow run id>
```

which copies the screenshots uploaded by that run (the job uploads them even
when the comparison fails) over the goldens. Commit the result.

`run.sh --update` still works for a quick local look, but comparing locally
against CI-rendered goldens will report a few percent of differing pixels
on other machines.
