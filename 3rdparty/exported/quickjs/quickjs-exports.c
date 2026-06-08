// This file is directly included in quickjs.c.

// The patch is from:
// https://www.freelists.org/post/quickjs-devel/Patch-Add-some-informations-to-get-more-informations-from-compiled-modules

int JS_GetModuleExportEntriesCount(JSModuleDef *m)
{
    return m->export_entries_count;
}

JSValue JS_GetModuleExportEntry(JSContext *ctx, JSModuleDef *m, int idx)
{
    if (idx >= m->export_entries_count || idx < 0)
        return JS_UNDEFINED;
    return JS_DupValue(ctx, m->export_entries[idx].u.local.var_ref->value);
}

JSAtom JS_GetModuleExportEntryName(JSContext *ctx, JSModuleDef *m, int idx)
{
    if (idx >= m->export_entries_count || idx < 0)
        return JS_ATOM_NULL;
    return JS_DupAtom(ctx, m->export_entries[idx].export_name);
}
