# Local QuickJS patches

The release snapshot in `3rdparty/exported/quickjs/` remains byte-for-byte
identical to upstream. `cmake/quickjs.cmake` uses GNU `patch` to apply the patches
below, in numbered order, to a generated `quickjs/quickjs.c` in the build
directory. Only that copy is compiled; the source checkout and vendored dependency
verification are unchanged.

The build regenerates the copy whenever the upstream source or either patch
changes. Patch application disables fuzz and automatic reversal, and a failure
stops the build rather than compiling an unpatched source.

## 0001-retain-exception-during-backtrace.patch

- Upstream issue: <https://github.com/bellard/quickjs/issues/533>
- Applies to QuickJS `2026-06-04`, commit
  `3d5e064e9dd67c70f7962836505a7fa067bf0a4e`.
- `build_backtrace()` borrows the pending exception. If another allocation fails
  while constructing the trace, `JS_Throw()` can replace and free that exception
  before its `stack` property is written. The patch holds a reference for the
  duration of backtrace construction and releases it, along with the trace
  buffer, on every exit.
- Regression coverage: `QuickJS handles OOM while constructing a backtrace` in
  `src/js/test/js.cpp` and the existing `auth` end-to-end heap-limit tests.

Remove the patch and its CMake application when upgrading to an upstream version
that fixes the lifetime of the exception in `build_backtrace()`. Keep the
regression coverage.

## 0002-enforce-lowered-heap-limit.patch

- CCF compatibility patch for QuickJS `2026-06-04`.
- The new arena allocator can satisfy small allocations and in-place
  reallocations without checking the memory limit. If CCF lowers the limit below
  the runtime's existing allocations, those operations can still succeed.
- Reject nonzero allocations and arena reallocations when accounted heap usage
  already exceeds the limit. Freeing memory, including zero-sized reallocations,
  remains possible. This is a constant-time check; it does not scan the heap,
  raise limits, or disable arenas.
- Regression coverage: `QuickJS rejects arena allocations above a lowered heap
  limit` in `src/js/test/js.cpp` and the unchanged `auth` end-to-end heap-limit
  tests in both Debug and Release builds.

Remove this patch and its CMake application when upstream provides equivalent
lowered-limit enforcement. Keep the regression coverage.
