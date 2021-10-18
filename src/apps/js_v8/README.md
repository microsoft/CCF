# V8 Experiment

This is an experiment to replace `quickjs` with V8.

The main gains from V8 are:
* It's a production JS engine used in Chrome, Electron, Node.js and other large-scale projects.
* It can JIT-compile to machine code, substantially increasing performance of common workloads.
* It supports WebAsm in additional to ECMAScript, opening CCF to accept more than just JS-like user code.
* It's security-focused to work in a hostile environment (browsers).

The main problems are:
* SGX doesn't allow execution on writable pages, which means JIT is out of the question.
* V8 development is fast paced and focused on browser-like workloads, which may provide friction to upgrading versions (in order to keep up with security features).
* Engine bring-up and configuration is way more complex than `quickjs`.
* There may be calls from within V8 that violate enclave requirements.

The answers to those problems are:
* SGX is an old extension that is getting replaced with better alternatives from AMD, Arm and probably Intel, soon.
* V8 has a `jitless` mode, that does not compile anything. We're hoping its interpreter is faster than `quickjs`, including the initial bring-up.
* Using the Virtual environment for current testing, and then AMD hardware for a hardware-backed enclave JIT execution is the plan.
* V8 versions tend to stick around much longer than other fast-paced projects (like LLVM), and the oldest stable release (9.4.146.*) is still receiving updates.
* This complexity is actually a great benefit. We can slice the bring-up into CCF bootstrap, endpoint bootstrap and execution, to only parse the script at the last part, hopefully also caching previously-parsed scripts (with same global context) to speed things up even further.
* We may be able to reduce the scope of the V8 execution to avoid enclave violations, or at least restrict in which kind of environment they execute on (ex. only AMD).

## Code layout

The V8 endpoint code has the same layout as the generic JS one, but with some logic distributed to minimise the impact of JIT platform cofiguration (for now, at endpoint creation).

So far, there are a lot of comments on what to do in V8 that is similar to generic, but not a lot of code that does so. That part should be better understood after reading the V8 docs, particularly:

https://v8.dev/docs/embed

There's also a new pair of files: `v8httpproc.{cpp|h}`. Those were copied from `v8:samples/process.cc` and, for now, do a lot more than what we need, and in a slightly _wrong way_.

We want to make the function called generic (by name, form the endpoint context), receive an `Object` as a result, and handle that back via HTTP Response.

The example does a bit of that, including: handling HTTP requests and responses, JIT compile of the whole script, finding symbols, etc.

The engine itself also does the caching and optimisation of JITed blocks, but we may have to plug into that to make sure it counts all global state as part of the matching, and re-compiles if the state changes.

I'm not sure all the map logic in `v8httpproc` makes sense, but didn't remove because it might be usefull.

## Compiling & Testing

Right now, the code does not compile. We still need to finish the V8 logic inside, and testing that will be a bit painful before we can actually call the end-to-end testing on it.

For now, I propose we have a `main.cpp` that calls the endpoint library as CCF would, and links `libjsv8.so` for a manual testing.

Once that's reasonably complete, we need to change the `e2e_logging.py` test to use the V8 library instead of `js_generic`. Those tests should pass completely before we can call it minimal support.

## Success Stories

There are two main success stories:

1. **Partial success:** V8 provides all security features we need without breaking CCF's guarantees, and also without making any extraneous systemcalls or file system usage that would make it impossible to use even in a virtual environment. Eventually, this becomes the default for AMD hardware.
2. **Full success:** All of the above, plus V8 `jitless` mode is at least as fast as `quickjs` and none of its calls violate SGX enclave restrictions, in a way that we can completely remove `quickjs` and replace all solutions with V8.

## Future Work

After introducing V8 to CCF, there are a number of things that can be done to improve performance:
* Cache script+context, to recall instead of recompiling.
* Cache the machine code directly, too.
* Allow programmers to choose between JIT and JITless depending on the turn-over of new scripts.
* Detect repetition and trigger re-compilation with new global context.

One issue with caches is that they could grow indefinitely, if not careful. But since each application has a finite set of scripts in the KV storage, and those are replaced by new versions, we can potentially know when a new script is replacing an old and replace the cached version (instead of adding a new one).

The main difficulty is separating between "same script, different global context" and "different script for the same functionality". As long as we pick the right map keys for the level of cache (see above) we should be fine in not proliferating cached entries on all nodes.