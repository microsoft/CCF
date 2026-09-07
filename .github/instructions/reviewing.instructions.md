---
applyTo: "**/*.cpp,**/*.h,**/*.hpp,**/*.cc,**/*.c"
---

# Security/safety review guidance and C/C++ conventions

The security/safety guidance applies to security-sensitive reviews in any language, as linked from the global instructions. The `applyTo` patterns additionally load this file for C/C++ changes; the C++ conventions and library-specific sections apply only where relevant.

## Security and safety first

CCF's primary review concern is preserving its security guarantees and distributed-system safety. Review confidentiality, authentication/authorization, data and ledger integrity, consensus safety, and resistance to denial of service before performance or convenience. A safety violation matters even without a demonstrated attacker.

- Identify the trust boundary and who controls each input: unauthenticated clients, users, members, peer nodes, or the untrusted host. Do not assume authenticated input is well-formed or authorized for every operation.
- Trace validation through the protected operation, including forwarding, asynchronous callbacks, retries, recovery, and rollback. A check is insufficient if the checked identity/state can change before use or if another path bypasses it.
- Check that failures leave state consistent and do not expose secrets, grant access, or continue using partially validated data. Distinguish rejected input from retryable outcomes and internal invariant failures; do not turn attacker-controlled errors into process-wide termination.
- Require regression coverage appropriate to the changed invariant: malformed and boundary inputs, unauthorized callers, and relevant lifetime or commit/rollback interleavings. Follow the testing skill rather than adding unrelated tests or tools.
- For each finding, identify the changed location, controllable input or triggering interleaving, missing protection, and concrete consequence. State uncertainty and prerequisites; historical similarity alone is not evidence of a current vulnerability.

### Patterns from past CCF fixes

These merged PRs are examples of security hardening and safety/correctness fixes, not a claim that each was a disclosed vulnerability. Apply the underlying invariant to the current diff and supported release; do not copy historical implementation details blindly.

- **Bind authenticated claims to the trusted identity.** [JWT issuer validation (#6175)](https://github.com/microsoft/CCF/pull/6175) added framework validation of token `iss` against signing-key issuer metadata. Check issuer/tenant binding and the endpoint's required claims and permissions, not just signature validity or key lookup. Negative tests should include correctly signed tokens from the wrong issuer and missing required claims.
- **Validate cryptographic material when admitting it.** [Constitution validation (#7924)](https://github.com/microsoft/CCF/pull/7924) hardened JWKS, CA, and member-key inputs. Check uniqueness of key identifiers, permitted key types/algorithms/uses, key strength, certificate structure, and issuer URL constraints against the service's policy. For CCF's root-CA bundle policy, verify root status rather than accepting an intermediate as an unintended trust anchor. Governance authorization does not replace input validation.
- **Preserve the complete attestation trust contract.** [ARK pinning (#7934)](https://github.com/microsoft/CCF/pull/7934) added issuer and algorithm checks alongside pinned public-key comparison; [attestation validation ordering (#7295)](https://github.com/microsoft/CCF/pull/7295) moved certificate validation ahead of report-content checks. Verify the expected chain, pinned metadata, report signature, and required report policy before trusting or returning claims. Necessary pre-verification parsing must be bounded and must not authorize actions or expose unverified outputs.
- **Verify TLS peer identity without broadening trust.** [Node join client migration (#8040)](https://github.com/microsoft/CCF/pull/8040) enforced hostname verification and prevented fallback to the host CA store. Check both certificate-chain validation and the expected peer name: SNI alone is not verification. Where a service certificate is the sole intended anchor, preserve that restriction across client/library changes. Test wrong names and wrong trust anchors.
- **Bound sizes before allocation, access, and state mutation.** [Maximum ledger transaction size (#7992)](https://github.com/microsoft/CCF/pull/7992) hardened ledger length handling and rejected oversized new transactions before applying changes. Check declared lengths against available bytes, overflow-safe offset arithmetic, allocation limits, and relationships between transaction and transport limits. Include truncated, oversized, and duplicate-message paths; preserve documented historical-ledger compatibility rather than imposing new-write limits indiscriminately on old entries.
- **Check representable ranges before conversion and arithmetic.** [Time point parsing bounds (#7648)](https://github.com/microsoft/CCF/pull/7648) fixed certificate-time overflow beyond the nanosecond clock range. Check externally supplied time/size values at every narrowing or unit conversion, including intermediate arithmetic. Test values at and beyond the supported bounds; a valid ASN.1 time is not necessarily representable by the selected C++ clock.
- **Audit consensus index semantics across term transitions.** [Retaining signatures during soft rollback (#5749)](https://github.com/microsoft/CCF/pull/5749) corrected use of a current-term committable index where the last signature across terms was needed. Trace all affected consumers when changing an index's meaning; distinguish signed, committed, unsigned, and term-local state. Review rollback/recovery paths as well as the happy path, and use existing scenario/model tests for the affected transition.
- **Create host files with restrictive permissions and safe ownership.** [Host-created file permissions (#7916)](https://github.com/microsoft/CCF/pull/7916) used explicit `0600` creation permissions rather than relying on umask. Check permissions at creation, preservation of exclusive-create semantics where required, and descriptor cleanup if wrapping/opening fails. Prefer the existing file helpers. These controls limit accidental local exposure; they do not make the host trusted or replace CCF's confidentiality protections.

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
