# CCF Patches to QuickJS

Upstream version: **2024-01-13** (https://bellard.org/quickjs/)

## Patch: Module Export Introspection

**Files**: `quickjs-exports.c`, `quickjs-exports.h`, and a `#include` in `quickjs.c` (line ~36844)

**What it does**: Adds three functions that allow C callers to enumerate a module's export entries:

- `JS_GetModuleExportEntriesCount(JSModuleDef *m)` — returns the number of exports
- `JS_GetModuleExportEntry(JSContext *ctx, JSModuleDef *m, int idx)` — returns the value of the export at index `idx`
- `JS_GetModuleExportEntryName(JSContext *ctx, JSModuleDef *m, int idx)` — returns the atom (name) of the export at index `idx`

**Why it's included via `#include` in quickjs.c**: These functions access the internal `JSModuleDef` struct (specifically `m->export_entries_count`, `m->export_entries[idx].u.local.var_ref->value`, and `m->export_entries[idx].export_name`). This struct is defined only inside `quickjs.c` and not exposed in any public header, so the code must be compiled within the same translation unit.

**Where CCF uses it**: `src/js/core/context.cpp` (around line 288) calls these functions to enumerate the exports of a loaded JS application module at registration time, allowing CCF to discover and register HTTP endpoint handlers defined in user JS code.