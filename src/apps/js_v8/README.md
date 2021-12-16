# V8 Experiment

This is an experiment to replace `quickjs` with V8.

The main gains from V8 are:

- It's a production JS engine used in Chrome, Electron, Node.js and other large-scale projects.
- It can JIT-compile to machine code, substantially increasing performance of common workloads.
- It supports Wasm in addition to ECMAScript, opening CCF to accept more than just JS-like user code.
- It's security-focused to work in a hostile environment (browsers).

The main problems are:

- SGX doesn't allow execution on writable pages, which means JIT is out of the question.
- V8 development is fast paced and focused on browser-like workloads, which may provide friction to upgrading versions (in order to keep up with security features).
- Engine bring-up and configuration is way more complex than `quickjs`.
- There may be calls from within V8 that violate enclave requirements.

The answers to those problems are:

- While CCF currently uses SGX, other platforms that CCF intends to target in the near future such as AMD SEV-SNP do not have the same limitations.
- V8 has a `jitless` mode, that does not compile anything. We're hoping its interpreter is faster than `quickjs`, including the initial bring-up.
- We can test JIT functionality in virtual mode, which is a good approximation for VM-based TEEs that we intend to target.
- V8 versions tend to stick around much longer than other fast-paced projects (like LLVM), and the oldest stable release (9.4.146.\*) is still receiving updates.
- This complexity is actually a great benefit. We can slice the bring-up into CCF bootstrap, endpoint bootstrap and execution, to only parse the script at the last part, while relying on V8 to cache previously-parsed scripts to speed things up even further.
- We may be able to reduce the scope of the V8 execution to avoid enclave violations, or at least restrict in which kind of environment they execute on.

## Compiling

New CMake options:

- `-DENABLE_V8=ON|OFF`: Enables building of the V8 app library, disabled by default.
- `-DV8_DEBUG=ON|OFF`: Whether to use the debug or release variant of V8, defaults to release.

See `scripts/v8` for tools to help with building/downloading V8.
