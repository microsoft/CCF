# V8 Patches

Whenever CCF decides to use a newer Clang version, then the patch file(s) in this folder must be updated to use the new libc++ paths corresponding to that compiler version. See also comments in `../build-v8.sh`.

Note that `ldflags` is only relevant for V8 build-time tools but the paths must match what is defined in `cflags_cc`.
