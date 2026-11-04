# Applications Page Refactor: Business Logic Owns the View

## What this is

This is a **heavy structural refactor** — not cleanup for its own sake.
The goal is to make the view fully *dependent on* business logic.
GTK must never decide what to render by inspecting runtime flags, checking `id().is_none()`,
or toggling `action_set_enabled` at scattered callsites.
The business layer decides what is valid; GTK only renders what is handed to it.

This means touching `src/devices/app.rs`, `src/ui/pages/applications/`, and the UI definition
at the same time if needed. Do not be timid. Rework whatever needs reworking.

## Core principle

> **The business layer must produce a view model. GTK renders the view model. GTK does not inspect raw business objects.**

The memory page (`src/ui/pages/memory.rs`) already does this:
- `refresh_page(memdata: MemoryData)` receives a typed snapshot.
- A pure Rust function (`swap_ui_state(...)`) derives a typed `SwapUiState` enum from that data.
- GTK pattern-matches on the enum to decide what to show. No flags, no runtime checks.

The applications page must reach the same level.

## What needs to change

### 1. `src/devices/app.rs` — business layer produces the view model

- `App` must expose a method (e.g. `action_mode() -> AppActionMode`) that returns what actions are valid.
- `AppActionMode` is a clean enum owned in the business layer, not in the UI module.
- `GroupOfProcesses` / system-processes rows must return an information-only mode at the source.
- GTK code must never re-derive this from `app.id().is_none()` or `app.is_system_processes_entry`.
  Those fields are business facts; the view model must translate them once, at source.

### 2. `src/ui/pages/applications/application_entry.rs` — GObject carries the view model

- `ApplicationEntry` GObject holds the `AppActionMode` (or an equivalent typed value) as a GObject property.
- GTK expression bindings / `connect_selection_changed` read the property; they do not compute mode themselves.
- No raw integer kind encoding. No `to_i32` / `from_i32`. Removed entirely.
- `ApplicationEntry::new(app, context)` and `update(app, context)` set the mode from `app.action_mode()` directly.

### 3. `src/ui/pages/applications/mod.rs` — GTK only renders

- `ResApplications` does **not** contain logic for what actions are allowed.
- `setup_signals`, `add_gestures`, `refresh_apps_list` only read what `ApplicationEntry` exposes.
- One function translates `AppActionMode` into GTK action enable/disable state. Nothing else does.
- `open_app_action_dialog` does not guard based on entry kind — by the time it is reachable the mode has already gated the action.

### 4. UI file — menus are driven by action state, not by code-level hacks

- `data/resources/ui/pages/applications.ui` uses `hidden-when="action-disabled"` for all destructive items.
- No menu item is conditionally visible by code toggling a separate boolean.
- `GroupOfProcesses` rows expose **only** the Information item in the context menu and show no End/Kill/Halt/Continue.

## Scope permission

Refactoring across multiple files at once is explicitly permitted and expected.
If a clean solution requires moving types between modules or renaming structs, do it.
Do not preserve old code paths "for compatibility" — this is a strict migration.

## Commits

Make a commit after each of these milestones so changes can be verified manually:

1. `AppActionMode` defined in `src/devices/app.rs` and `App::action_mode()` implemented.
2. `ApplicationEntry` GObject stores `AppActionMode`; `new`/`update` set it from `App`.
3. `ResApplications` wiring refactored to consume `AppActionMode`; scattered flags removed.
4. UI file and dialog aligned; compile passes; manual smoke-test done.

## Reference point: memory page swap-state pattern

```
src/ui/pages/memory.rs

fn swap_ui_state(is_separate: bool, swap_devices: &[SwapDevice], usage: Option<SwapUsage>) -> SwapUiState

enum SwapUiState {
    Hidden,
    Combined { usage, show_options },
    PerDevice(PerDevice),
}

// GTK:
match swap_state {
    SwapUiState::Hidden => { imp.swap.set_visible(false); ... }
    SwapUiState::Combined { ... } => { ... }
    SwapUiState::PerDevice(...) => { ... }
}
```

This is the pattern. `applications` must reach the same level of cleanliness.

## Relevant history

- `4c89158237d42b99b4b924cedd1ce975b807bc09`
- `5448aa80def52f424135db6a268295812d752bd4`
- `e108e305149552f1647bfdc329b6e488258513ea`
- `993adb9b8fe619390c6a81c971d3a3d4440f3c13`
- `7bd4aa98f4a03798d5cabaeb6aae79aba9c51c0b`
- `e8a20e02194dc33cc591c26397c5649a52e28fc0`
- `5b85984426062e7b4680def3ba537e34d1c47f0e`
