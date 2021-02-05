#pragma once

#include "quickjs.h"

// See quickjs-extras.c for details.

extern "C" {

int JS_GetModuleExportEntriesCount(JSModuleDef *m);
JSValue JS_GetModuleExportEntry(JSContext *ctx, JSModuleDef *m, int idx);
JSAtom JS_GetModuleExportEntryName(JSContext *ctx, JSModuleDef *m, int idx);
void JS_ResetTopOfStack(JSRuntime *rt);

}
