# Local QuickJS patches

The vendored snapshot is upstream commit `e585640ffa2cf88ce7c2d587583c6fe15928ec2f`.
`cmake/quickjs.cmake` applies the patches in numbered order to a generated copy of `quickjs.c`, leaving the vendored source unchanged.
Patch application disables fuzz and automatic reversal, and a failure stops the build.

## 0001-free-backtrace-buffer.patch

Upstream fixed the exception lifetime issue in `build_backtrace()` in commit `cd97c2b4a85a0cbd3bf3a56681c2d2c92f4bda68`, but its early exits still skip freeing the initialized backtrace buffer.
This patch frees the buffer on every exit.
The exception lifetime regression remains covered by `QuickJS handles OOM while constructing a backtrace` in `src/js/test/js.cpp`.

## 0002-enforce-lowered-heap-limit.patch

The arena allocator can satisfy small allocations and in-place reallocations without checking the memory limit.
When CCF lowers the limit below the runtime's existing allocations, the patch rejects nonzero allocations and arena reallocations while still permitting frees.
The `QuickJS rejects arena allocations above a lowered heap limit` test and the `auth` end-to-end heap-limit tests cover this behavior.
Remove this patch when upstream provides equivalent enforcement.

## 0003-commit-growable-shared-array-buffer.patch

`SharedArrayBuffer.prototype.grow()` only raises the buffer's length, on the assumption that its maximum length was allocated on construction.
That is only true when the embedder installs shared buffer allocation functions, which CCF does not, so growing a buffer exposed adjacent heap memory to out-of-bounds reads and writes from JavaScript.
This patch allocates the maximum length on construction, where it also counts against the heap limit.
The `QuickJS commits the maximum length of growable SharedArrayBuffers` test in `src/js/test/js.cpp` covers this behavior.
Remove this patch when upstream allocates the maximum length or reallocates on growth.

## 0004-defer-memory-limit-during-compilation.patch

The parser and bytecode compiler do not handle failed allocations safely: after a failure they can index buffers which were not grown, corrupting memory.
A script compiled while the heap is near its limit, including through `eval`, `new Function` and module loading, could therefore crash or corrupt the node.
This patch lifts the heap limit while a script is parsed and compiled, and instead tests it where the compiler can stop with an out of memory error: before each token, before each function's source text is copied, and before each function is emitted.
Once a test has failed, every later one fails too, because the parser ignores some errors while looking ahead and must not resume if a garbage collection then frees memory.
The limit is restored before any compiled code runs.
Memory use can exceed the limit by the allocations made between two tests, the largest being the code generation for a single function, so a script can compile successfully although its peak use was above the limit.
Allocation failures reported by the system allocator itself are not covered, and neither is loading cached bytecode, which does not use the compiler.
This patch relies on `0002-enforce-lowered-heap-limit.patch` to reject further allocations once compilation has left the heap above its limit.
The `QuickJS reports out of memory when compiling above the heap limit`, `QuickJS bounds heap use when compiling nested arrow functions` and `QuickJS does not resume compiling after exceeding the heap limit` tests in `src/js/test/js.cpp` cover this behavior.
Remove this patch when the upstream compiler handles allocation failure.

## 0005-release-module-on-failed-read.patch

`JS_ReadModule()`, which loads a module from cached bytecode, leaves an incomplete module behind when it fails, for instance because the heap limit is reached.
The module records the size of each of its entry tables before allocating it, so if that allocation fails, freeing or garbage collecting the module dereferences a null table.
The module also stays loaded in its context, so a later import of the same name uses it instead of loading it again, and dereferences its missing function.
Either crashes the node.
This patch clears the size of any table which was not allocated, and releases the context's reference so that the module is freed and can be loaded again.
The `QuickJS frees a module which could not be read from bytecode` and `QuickJS reloads a module after failing to read it from bytecode` tests in `src/js/test/js.cpp` cover this behavior.
Remove this patch when upstream releases the module on failure.
