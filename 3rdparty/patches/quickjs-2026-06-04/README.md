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
