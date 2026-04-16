---
applyTo: "**/*.cpp,**/*.h,**/*.hpp,**/*.cc,**/*.c"
---

# Code review – third-party library error handling

When flagging a third-party error-handling issue during review, cite this file (`.github/instructions/reviewing.instructions.md`) so the author can look up the full guidelines.

When reviewing any C++ change that adds or modifies calls to OpenSSL (or another third-party C library), apply the checks below. The goal is to catch unchecked return values and inconsistent error-handling patterns before they reach production.

## General principles

1. **Every call that can fail must be checked.** If a C function documents a failure return (error code, null pointer, negative value, …), the caller must test for it. Silently discarding the result is always a defect in this codebase.
2. **Use the project's own helpers.** CCF already provides wrapper macros and RAII types for the most common libraries (see tables below). Prefer those over ad-hoc `if` checks so that error messages stay consistent and nothing is accidentally skipped.
3. **Consistent style within a function.** If the first half of a function uses `CHECK1()` for every OpenSSL call but the second half silently ignores a return value, flag the inconsistency even if the ignored call "usually succeeds."
4. **Clean up on every error path.** When RAII wrappers are not used, verify that every early-return or throw after a partial allocation frees the already-acquired resources.

## OpenSSL

CCF wraps OpenSSL with helpers defined in `include/ccf/crypto/openssl/openssl_wrappers.h`.

### Available check macros

| Macro                        | Use when the OpenSSL function …                                   |
| ---------------------------- | ----------------------------------------------------------------- |
| `CHECK1(rc)`                 | returns **1** on success (most `EVP_*`, `BN_*`, `X509_*` setters) |
| `CHECK0(rc)`                 | returns **0** on success (rare; e.g. some comparison helpers)     |
| `CHECKNULL(ptr)`             | returns a **pointer** that is null on failure                     |
| `CHECKPOSITIVE(val)`         | returns a **positive int** on success (e.g. `EVP_PKEY_CTX_set_*`) |
| `CHECKEQUAL(expect, actual)` | must return an **exact value**                                    |

### Available RAII wrappers (`Unique_*`)

`Unique_EVP_PKEY_CTX`, `Unique_BIO`, `Unique_PKEY`, `Unique_X509`, `Unique_X509_REQ`, `Unique_X509_CRL`, `Unique_SSL_CTX`, `Unique_SSL`, `Unique_BIGNUM`, `Unique_X509_TIME`, and others. These call the correct `*_free()` destructor automatically.

### What to look for

- **Allocations without `CHECKNULL`:** Any direct call to `EVP_PKEY_new()`, `BIO_new()`, `X509_new()`, `EVP_MD_CTX_new()`, `BN_new()`, `SSL_CTX_new()`, `SSL_new()`, or similar that stores the result without passing it through `CHECKNULL()` or an equivalent null check.
- **`CHECK1` vs `CHECKPOSITIVE` mix-ups:** Some OpenSSL functions (notably `EVP_PKEY_CTX_set_*`) return a positive value on success, not exactly 1. Using `CHECK1` on those calls will incorrectly treat valid return codes > 1 as failures and trigger false-positive error handling. Conversely, `CHECKPOSITIVE` is wrong for functions that return exactly 1 on success.
- **`BIO_get_mem_ptr` / `BIO_read` ignored:** These return an int indicating success. Verify the return is tested before dereferencing the output pointer.
- **Missing `ERR_get_error` drain on error paths:** When an OpenSSL failure is caught but the error queue is not drained (or vice-versa), later calls may see stale errors.
- **Raw `new`/`free` instead of RAII wrappers:** If a `Unique_*` type exists for the object, the review should suggest using it rather than manual `*_free()` calls.
- **Partial checks:** A sequence of OpenSSL calls where some are wrapped in a check macro and others are not is a red flag. All calls in the sequence should be checked.

### Consult the documentation

OpenSSL documents return values on its man pages (<https://docs.openssl.org/master/man3/>). When reviewing a call you are unfamiliar with, look up the specific function to confirm:

- What value indicates success (1, 0, positive, non-null, …).
- Whether the function sets the OpenSSL error queue on failure.
- Whether the caller must free the returned object.

Use this to verify that the correct check macro is used and that the error path is appropriate.

## libcurl

CCF wraps libcurl in `src/http/curl.h`.

| Macro                                        | Use when …                          |
| -------------------------------------------- | ----------------------------------- |
| `CHECK_CURL_EASY(fn, ...)`                   | calling any `curl_easy_*` function  |
| `CHECK_CURL_EASY_SETOPT(handle, opt, arg)`   | calling `curl_easy_setopt`          |
| `CHECK_CURL_EASY_GETINFO(handle, info, arg)` | calling `curl_easy_getinfo`         |
| `CHECK_CURL_MULTI(fn, ...)`                  | calling any `curl_multi_*` function |

### What to look for

- Direct calls to `curl_easy_setopt`, `curl_easy_perform`, or `curl_multi_*` that do not use the above macros.
- `curl_easy_init()` or `curl_multi_init()` returns not checked for null.
- `curl_slist_append()` return not checked for null (it returns null on allocation failure).

## llhttp (HTTP/1.x parser)

Used in `src/http/http_parser.h`. The parser entry point is `llhttp_execute()`; its return must be compared against `HPE_OK` (and, where relevant, `HPE_PAUSED_UPGRADE`).

### What to look for

- Calls to `llhttp_execute()` whose return value is not tested.
- Missing use of `llhttp_errno_name()` / `llhttp_get_error_reason()` in the error message (makes debugging harder).
- Callback return values: llhttp callbacks (e.g. `on_message_complete`) that return non-zero indicate a parse error to the library. Ensure these are intentional.

## nghttp2 (HTTP/2)

Used in `src/http/http2_callbacks.h` and `src/http/http2_session.h`. Most `nghttp2_*` functions return 0 on success or a negative error code.

### What to look for

- Calls to `nghttp2_session_*`, `nghttp2_submit_*`, or `nghttp2_hd_*` where the return value is silently discarded.
- Error messages that print only the raw integer code instead of `nghttp2_strerror(rc)`.
- `nghttp2_session_send()` / `nghttp2_session_mem_recv()` return values not checked.

## QuickJS

Used in `src/js/`. `JS_*` functions return `JSValue`; errors are indicated by `JS_IsException()`.

### What to look for

- `JS_Call`, `JS_Eval`, `JS_GetPropertyStr`, `JS_NewObject`, etc. whose return value is not passed through `JS_IsException()` (or an equivalent check) before use.
- Missing `JS_FreeValue()` on values that are no longer needed (leaks in the JS runtime).

## Other third-party libraries

For any other C library call added in a change (e.g. `uv_*` from libuv, zlib, or platform APIs), apply the same discipline:

1. Look up the function's documented return-value contract.
2. Confirm the call site checks for the failure case.
3. Confirm the error message includes enough context (function name, error code or string) to be debuggable.
4. Confirm resources are released on the error path.

## Checklist for reviewers

Use this as a mental checklist when reviewing a diff that touches third-party library calls:

- [ ] Every function that can fail has its return value checked.
- [ ] The correct check macro/pattern is used (e.g. `CHECK1` vs `CHECKPOSITIVE` for OpenSSL).
- [ ] All allocations are null-checked, ideally via RAII wrappers.
- [ ] Error handling is consistent within each function — no unchecked calls mixed with checked ones.
- [ ] Error messages include the library's own error string (e.g. `error_string(ec)`, `nghttp2_strerror(rc)`).
- [ ] Resources allocated before the failing call are freed on the error path.
- [ ] No OpenSSL error-queue state is leaked across unrelated operations.
