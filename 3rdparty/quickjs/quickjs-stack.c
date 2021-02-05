// This file is directly included in quickjs.c.

void JS_ResetTopOfStack(JSRuntime *rt)
{
    rt->stack_top = js_get_stack_pointer();
}
