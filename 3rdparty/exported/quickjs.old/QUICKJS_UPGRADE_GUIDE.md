# QuickJS Upgrade Guide: Module Export API Migration

## Overview

When upgrading from QuickJS **2024-01-13** to **2025-09-13**, CCF's custom
module export introspection patch (`quickjs-exports.c`, `quickjs-exports.h`,
and the `#include` in `quickjs.c`) can be **removed entirely**. The new
upstream release provides `JS_GetModuleNamespace()` as a public API that
serves the same purpose.

## Current CCF patch API (to remove)

```c
// quickjs-exports.h
int JS_GetModuleExportEntriesCount(JSModuleDef *m);
JSValue JS_GetModuleExportEntry(JSContext *ctx, JSModuleDef *m, int idx);
JSAtom JS_GetModuleExportEntryName(JSContext *ctx, JSModuleDef *m, int idx);
```

## New upstream API (2025-09-13)

```c
// quickjs.h — already public, no patch needed
JSValue JS_GetModuleNamespace(JSContext *ctx, JSModuleDef *m);

// Also new: helper to free property enums (previously internal-only)
void JS_FreePropertyEnum(JSContext *ctx, JSPropertyEnum *tab, uint32_t len);

// Already existed in 2024-01-13:
int JS_GetOwnPropertyNames(JSContext *ctx, JSPropertyEnum **ptab,
                           uint32_t *plen, JSValueConst obj, int flags);
```

`JS_GetModuleNamespace()` returns the module's namespace object — a regular
JS object where each property corresponds to a named export.

## Migration

### Current code (`src/js/core/context.cpp` ~line 285)

```cpp
// Get exported function from module
assert(JS_VALUE_GET_TAG(module.val) == JS_TAG_MODULE);
auto* module_def =
  reinterpret_cast<JSModuleDef*>(JS_VALUE_GET_PTR(module.val));
auto export_count = JS_GetModuleExportEntriesCount(module_def);
for (auto i = 0; i < export_count; i++)
{
  auto export_name_atom = JS_GetModuleExportEntryName(ctx, module_def, i);
  auto export_name = to_str(export_name_atom);
  JS_FreeAtom(ctx, export_name_atom);
  if (export_name.value_or("") == func)
  {
    auto export_func = wrap(JS_GetModuleExportEntry(ctx, module_def, i));
    if (JS_IsFunction(ctx, export_func.val) == 0)
    {
      throw std::runtime_error(fmt::format(
        "Export '{}' of module '{}' is not a function", func, path));
    }
    return export_func;
  }
}
```

### Replacement code

```cpp
// Get exported function from module via namespace object
assert(JS_VALUE_GET_TAG(module.val) == JS_TAG_MODULE);
auto* module_def =
  reinterpret_cast<JSModuleDef*>(JS_VALUE_GET_PTR(module.val));
auto ns = wrap(JS_GetModuleNamespace(ctx, module_def));
if (JS_IsException(ns.val))
{
  throw std::runtime_error(
    fmt::format("Failed to get namespace for module '{}'", path));
}

auto func_atom = JS_NewAtom(ctx, func.c_str());
auto export_func = wrap(JS_GetPropertyInternal(ctx, ns.val, func_atom, ns.val, FALSE));
JS_FreeAtom(ctx, func_atom);

if (JS_IsUndefined(export_func.val))
{
  throw std::runtime_error(
    fmt::format("Failed to find export '{}' in module '{}'", func, path));
}
if (JS_IsFunction(ctx, export_func.val) == 0)
{
  throw std::runtime_error(fmt::format(
    "Export '{}' of module '{}' is not a function", func, path));
}
return export_func;
```

This is simpler — instead of iterating all exports to find one by name, it
does a direct property lookup on the namespace object.

### Alternative: if you need to enumerate all exports

If other callsites need to iterate all exports (not just look up by name):

```cpp
auto* module_def =
  reinterpret_cast<JSModuleDef*>(JS_VALUE_GET_PTR(module.val));
auto ns = wrap(JS_GetModuleNamespace(ctx, module_def));

JSPropertyEnum* tab = nullptr;
uint32_t tab_len = 0;
if (JS_GetOwnPropertyNames(ctx, &tab, &tab_len, ns.val,
                            JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) < 0)
{
  throw std::runtime_error("Failed to enumerate module exports");
}

for (uint32_t i = 0; i < tab_len; i++)
{
  auto name = JS_AtomToCString(ctx, tab[i].atom);
  auto value = wrap(JS_GetProperty(ctx, ns.val, tab[i].atom));
  // ... use name and value ...
  JS_FreeCString(ctx, name);
}

JS_FreePropertyEnum(ctx, tab, tab_len);
```

## Files to remove after migration

1. `3rdparty/exported/quickjs/quickjs-exports.c` — patch implementation
2. `3rdparty/exported/quickjs/quickjs-exports.h` — patch header
3. `3rdparty/exported/quickjs/CCF_PATCHES.md` — this patch is the only one
4. Remove the `#include "quickjs-exports.c"` block from `quickjs.c` (~line 36844)
5. Remove the `#include <quickjs/quickjs-exports.h>` from
   `include/ccf/js/core/context.h`

## Other notes

- The `-DCONFIG_BIGNUM` flag in `cmake/quickjs.cmake` must be removed — the
  2025-04-26 release deleted BigNum extensions from QuickJS entirely.
  Standard `BigInt` (ES2023) remains built-in with no flag needed.
- The `DUMP_LEAKS` debug flag should still work.
- Check the QuickJS Changelog for any other API changes that affect
  `src/js/` code: https://bellard.org/quickjs/Changelog
