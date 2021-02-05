#pragma once

#include "quickjs.h"

// See quickjs-stack.c for details.

extern "C" {

void JS_ResetTopOfStack(JSRuntime *rt);

}
