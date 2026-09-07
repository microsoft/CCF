---
applyTo: "**/*.cpp,**/*.h,**/*.hpp,**/*.cc,**/*.c"
---

# C/C++ conventions and third-party library error handling

Use these conventions when implementing C++ changes and the error-handling guidance when implementing or reviewing C/C++ library calls.

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
