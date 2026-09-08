---
applyTo: "**/*.cpp,**/*.h,**/*.hpp,**/*.cc,**/*.c"
---

# Security/safety review guidance and C/C++ conventions

The security/safety guidance applies to security-sensitive reviews in any language, as linked from the global instructions. The `applyTo` patterns additionally load this file for C/C++ changes; the C++ conventions and library-specific sections apply only where relevant.

## ASCII-only authoring and review

- Apply the ASCII policy and Lean exception in the [repository instructions](/.github/copilot-instructions.md#task-boundaries).
- For files subject to the ASCII policy, check additions and modified text before committing or approving, including files outside `scripts/ascii-checks.sh` coverage. Report uncovered violations; do not duplicate findings already reported by the automated check.
- Keep fixes scoped to the current change. Do not rewrite unrelated existing Unicode fixtures, vendored files, or prose documentation.

## Security and safety first

CCF's primary review concern is preserving its security guarantees and distributed-system safety. Review confidentiality, authentication/authorization, data and ledger integrity, consensus safety, and resistance to denial of service before performance or convenience. A safety violation matters even without a demonstrated attacker.

- Identify the trust boundary and who controls each input: unauthenticated clients, users, members, peer nodes, or the untrusted host. Do not assume authenticated input is well-formed or authorized for every operation.
- Trace validation through the protected operation, including forwarding, asynchronous callbacks, retries, recovery, and rollback. A check is insufficient if the checked identity/state can change before use or if another path bypasses it.
- Check that failures leave state consistent and do not expose secrets, grant access, or continue using partially validated data. Distinguish rejected input from retryable outcomes and internal invariant failures; do not turn attacker-controlled errors into process-wide termination.
- Require regression coverage appropriate to the changed invariant: malformed and boundary inputs, unauthorized callers, and relevant lifetime or commit/rollback interleavings. Follow the testing skill rather than adding unrelated tests or tools.
- For each finding, identify the changed location, controllable input or triggering interleaving, missing protection, and concrete consequence. State uncertainty and prerequisites; matching a risk pattern alone is not evidence of a vulnerability.

### Security and safety review approaches

Apply these approaches to the paths affected by the diff, including called libraries and shared helpers, rather than limiting review to the edited lines.

- **Prioritize processing reachable before authentication.** Trace all potentially unauthenticated data processing, including parsing performed to verify credentials or signatures. Check for stack overflow from unbounded recursion or nesting, out-of-bounds access, use-after-free, and attacker-controlled allocations. Authentication later in the pipeline does not protect earlier processing.
- **Bound resource consumption end to end.** Verify limits on input size, nesting depth, element counts, allocation growth, CPU work, and concurrent or queued requests. A byte-size limit alone does not bound stack depth or computational complexity. Enforce limits before expensive processing and reject excess work without terminating the node.
- **Bind claims and permissions to the authenticated identity.** Verify that identity claims satisfy trusted issuer, tenant, audience, and validity constraints required by the policy. Check authorization for the actual operation and resource; a valid signature or successful key lookup is not sufficient.
- **Validate cryptographic material at admission and use.** Check structural validity, unambiguous identifiers, permitted algorithms and key uses, key strength, and trust-anchor constraints. Authorized configuration changes still require validation; stored material must not acquire broader trust when consumed by another component.
- **Establish trust before using claims.** Verify the complete certificate/signature/attestation policy, including required metadata and peer identity, before returning trusted outputs or authorizing actions. Keep necessary pre-verification parsing bounded. Preserve intended trust anchors across library changes and fallback paths.
- **Validate lengths and arithmetic before acting on them.** Check declared lengths against available bytes, overflow-safe offsets, representable ranges, narrowing conversions, and intermediate unit/time arithmetic before allocation, access, or state mutation. Reconcile limits across protocol layers while preserving documented compatibility requirements.
- **Preserve consensus and transactional invariants across transitions.** Trace all consumers when changing state or index semantics. Distinguish signed, committed, speculative, and term-local state; check atomicity of validation and mutation across concurrency, retries, term changes, rollback, and recovery. Rejected work must not leave state or metadata inconsistent.
- **Protect data throughout its lifetime.** Trace sensitive data through memory ownership, logging, responses, and persistent files. Use restrictive access at file creation, preserve exclusive-create guarantees where required, and release resources on partial failure. Host-side access controls do not make the host trusted or replace cryptographic confidentiality protections.

## C++ conventions

- Use `PascalCase` for classes/structs; `snake_case` for functions, members (no prefix), namespaces, and filenames; `UPPER_SNAKE_CASE` for constants. Use `#pragma once` for headers.
- Use `DECLARE_JSON_*` macros from `include/ccf/ds/json.h` for struct serialisation, selecting required, optional, and base fields to match the data contract.
- Register endpoints in `init_handlers()`: `make_endpoint` for read-write transactions, `make_read_only_endpoint` for read-only transactions, and `make_command_endpoint` for no KV access. Select authentication and forwarding policies explicitly for the endpoint's semantics; follow nearby handlers rather than copying an arbitrary policy.
- Access typed KV maps through transaction handles (`tx.rw` or `tx.ro`), not directly. Handle absent values returned by `get`.
- Use `CCF_APP_*` logging macros in applications and `LOG_*_FMT` macros from `src/ds/internal_logger.h` internally. Levels, in decreasing verbosity: `TRACE`, `DEBUG`, `INFO`, `FAIL`, `FATAL`.
- Prefer existing RAII wrappers and smart pointers. Follow surrounding comment density; explain invariants or non-obvious behaviour, not the history of an edit.

## Error-handling review method

1. Establish the specific API's return-value and ownership contract using the version shipped by the repository, its headers, wrappers, and matching documentation. Do not infer a contract from a function-name prefix.
2. Check whether failure is handled locally, by a wrapper, or by propagation to the caller. Distinguish failures from normal outcomes such as verification mismatch, EOF, retry, or absent properties.
3. Prefer existing check helpers when their success predicate and throwing behaviour fit the call site. Explicit checks are valid for recoverable errors, partial results, callbacks, and non-throwing cleanup.
4. Trace resource ownership through partial allocation, early return, exceptions, and ownership transfer. Do not add duplicate checks or frees when a wrapper already handles them.
5. Flag ignored failures when they cause incorrect behaviour or lose necessary diagnostics. Best-effort cleanup may intentionally ignore a result when it cannot affect correctness; verify that justification rather than treating every discarded return as a defect.
6. Explain the concrete failure path in a review finding. A different check style, manual ownership that is demonstrably correct, or a missing preferred error string alone is not a correctness defect.

## OpenSSL

CCF wraps OpenSSL with helpers defined in `include/ccf/crypto/openssl/openssl_wrappers.h`.

### Check helpers

| Helper                       | Success predicate  |
| ---------------------------- | ------------------ |
| `CHECK1(rc)`                 | `rc == 1`          |
| `CHECKNULL(ptr)`             | `ptr != nullptr`   |
| `CHECKPOSITIVE(val)`         | `val > 0`          |
| `CHECKEQUAL(expect, actual)` | `actual == expect` |

Choose the predicate from the individual API contract. `CHECK1` rejects valid values above 1 for APIs allowing any positive success result. `CHECKPOSITIVE` is also correct for an API whose only success is 1 and whose failures are all non-positive; do not flag that equivalence as a bug. These helpers throw, and `CHECKNULL` validates rather than returns the pointer.

- Existing `Unique_*` wrappers cover objects such as BIOs, keys, certificates, and SSL contexts. Verify the chosen constructor's allocation/null check and ownership semantics before adding another check.
- `BIO_get_mem_ptr` returns a control result and writes an output pointer; validate success before using that pointer. `BIO_read` returns a byte count, not a Boolean: handle short reads and the BIO's EOF/retry/error semantics.
- Inspect error-queue ownership at the recovery boundary. Preserve errors needed by the caller (notably before `SSL_get_error`); drain or clear stale errors only where the API contract and recovery flow require it. One `ERR_get_error()` removes one entry, not the entire queue.
- For unfamiliar APIs, consult the matching-version [OpenSSL documentation](https://docs.openssl.org/) for success values, error-queue behaviour, and whether returned objects are owned or borrowed.

## libcurl

CCF wraps libcurl in `src/http/curl.h`.

| Macro                                        | Applicable return contract      |
| -------------------------------------------- | ------------------------------- |
| `CHECK_CURL_EASY(fn, ...)`                   | `CURLcode`, success `CURLE_OK`  |
| `CHECK_CURL_EASY_SETOPT(handle, opt, arg)`   | `curl_easy_setopt`              |
| `CHECK_CURL_EASY_GETINFO(handle, info, arg)` | `curl_easy_getinfo`             |
| `CHECK_CURL_MULTI(fn, ...)`                  | `CURLMcode`, success `CURLM_OK` |

These macros throw; use explicit handling for recoverable transfer errors. They do not apply to pointer- or void-returning APIs. `curl_easy_init()` and `curl_multi_init()` need null checks, already provided by CCF's `UniqueCURL`/`UniqueCURLM` constructors. On `curl_slist_append()` failure, preserve ownership of the original list rather than overwriting its only pointer with null.

## llhttp (HTTP/1.x parser)

Used in `src/http/http_parser.h`. Check `llhttp_execute()` against `HPE_OK`, handling supported pause/upgrade outcomes explicitly. Callback return contracts differ; distinguish intentional pause/upgrade from parse errors using the shipped API. For parse failures, prefer diagnostics from `llhttp_errno_name()` / `llhttp_get_error_reason()`.

## nghttp2 (HTTP/2)

Used in `src/http/http2_callbacks.h` and `src/http/http2_session.h`. Many APIs return 0 on success and negative error codes, but others return counts or identifiers. In particular, `nghttp2_session_mem_recv()` returns consumed bytes on success; account for partial consumption. Check `nghttp2_session_send()` failures and prefer `nghttp2_strerror(rc)` in error diagnostics.

## QuickJS

Used in `src/js/`, with declarations in `3rdparty/exported/quickjs/quickjs.h`.

- Fallible `JSValue` producers such as `JS_Call`, `JS_Eval`, and `JS_GetPropertyStr` indicate exceptions via `JS_IsException()`. Check or propagate exceptions before treating the value as a successful result.
- Integer-returning APIs such as `JS_ToInt32` and `JS_SetPropertyStr` use their documented integer failure convention, not `JS_IsException()`.
- Pointer-returning constructors such as `JS_NewRuntime` need null checks; void-returning functions cannot be return-checked.
- Track owned, borrowed, duplicated, and consumed values. Free owned values no longer needed (or use existing RAII wrappers), but do not free values after a consuming API has taken ownership.

Apply the same contract-first review method to other libraries, including libuv, zlib, and platform APIs.
