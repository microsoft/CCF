// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C-ABI-specific FFI helpers: pointer/buffer marshaling built on the shared
//! [`crate::TavError`]/[`crate::TavErrorCode`] types.

use std::os::raw::c_char;

use crate::{TavError, TavErrorCode};

const NULL_ERROR_MESSAGE: &[u8] = b"null TavError pointer\0";

#[no_mangle]
pub unsafe extern "C" fn tav_error_code(error: *const TavError) -> TavErrorCode {
    if error.is_null() {
        return TavErrorCode::ErrorIsNull;
    }

    unsafe { (*error).code }
}

#[no_mangle]
pub unsafe extern "C" fn tav_error_message(error: *const TavError) -> *const c_char {
    if error.is_null() {
        return NULL_ERROR_MESSAGE.as_ptr().cast();
    }

    unsafe { (*error).message.as_ptr() }
}

#[no_mangle]
pub unsafe extern "C" fn tav_error_free(error: *mut TavError) {
    if !error.is_null() {
        unsafe {
            drop(Box::from_raw(error));
        }
    }
}

/// Opaque owned byte buffer returned by public C ABI functions.
///
/// Callers only ever hold a `*mut TavByteBuffer` produced by a library
/// function; they read it through [`tav_byte_buffer_data`]/[`tav_byte_buffer_len`]
/// and release it with [`tav_byte_buffer_free`]. Keeping the type opaque means a
/// caller cannot construct one over foreign memory, so every buffer passed to
/// [`tav_byte_buffer_free`] is guaranteed to have been allocated by this library.
pub struct TavByteBuffer {
    bytes: Box<[u8]>,
}

impl TavByteBuffer {
    /// Take ownership of `bytes` and box it as an owned C byte buffer.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Box<Self> {
        Box::new(Self {
            bytes: bytes.into().into_boxed_slice(),
        })
    }
}

/// Borrow the bytes owned by `buffer`.
///
/// The returned pointer is valid until `buffer` is freed and is non-null even
/// for a zero-length buffer, so always pair it with [`tav_byte_buffer_len`].
/// Returns null when `buffer` is null.
///
/// # Safety
/// `buffer` must be null or a live buffer returned by this library.
#[cfg(not(target_family = "wasm"))]
#[no_mangle]
pub unsafe extern "C" fn tav_byte_buffer_data(buffer: *const TavByteBuffer) -> *const u8 {
    if buffer.is_null() {
        return std::ptr::null();
    }
    let buffer = unsafe { &*buffer };
    buffer.bytes.as_ptr()
}

/// Return the number of bytes owned by `buffer`, or 0 when `buffer` is null.
///
/// # Safety
/// `buffer` must be null or a live buffer returned by this library.
#[cfg(not(target_family = "wasm"))]
#[no_mangle]
pub unsafe extern "C" fn tav_byte_buffer_len(buffer: *const TavByteBuffer) -> usize {
    if buffer.is_null() {
        return 0;
    }
    let buffer = unsafe { &*buffer };
    buffer.bytes.len()
}

/// Free a byte buffer produced by this library. Freeing null is a no-op.
///
/// # Safety
/// `buffer` must be null or a buffer returned by this library that has not
/// already been freed.
#[cfg(not(target_family = "wasm"))]
#[no_mangle]
pub unsafe extern "C" fn tav_byte_buffer_free(buffer: *mut TavByteBuffer) {
    if !buffer.is_null() {
        unsafe {
            drop(Box::from_raw(buffer));
        }
    }
}

/// Maximum size accepted for any single C ABI input buffer (1 GiB).
///
/// Bounds attacker-controlled lengths before they reach `slice::from_raw_parts`
/// and guards `count * stride` arithmetic in callers that read parallel arrays.
pub const MAX_INPUT_LEN: usize = 1024 * 1024 * 1024;

/// Borrow a caller-provided input buffer after validating its pointer and length.
///
/// # Safety
/// When `len` is non-zero, `data` must point to at least `len` readable bytes
/// that outlive `'a`.
#[cfg(not(target_family = "wasm"))]
pub unsafe fn input_bytes<'a>(
    data: *const u8,
    len: usize,
    name: &str,
    allow_empty: bool,
) -> Result<&'a [u8], TavError> {
    if len == 0 {
        if allow_empty {
            return Ok(&[]);
        }
        return Err(TavError::invalid_argument(format!("{name} is empty")));
    }
    if data.is_null() {
        return Err(TavError::invalid_argument(format!(
            "{name} pointer is null"
        )));
    }
    if len > MAX_INPUT_LEN {
        return Err(TavError::invalid_argument(format!(
            "{name} exceeds maximum input size"
        )));
    }
    Ok(unsafe { std::slice::from_raw_parts(data, len) })
}

/// Borrow a caller-provided UTF-8 input, validating pointer, length, and encoding.
///
/// # Safety
/// Same requirements as [`input_bytes`].
#[cfg(not(target_family = "wasm"))]
pub unsafe fn input_text<'a>(
    data: *const c_char,
    len: usize,
    name: &str,
    allow_empty: bool,
) -> Result<&'a str, TavError> {
    let bytes = unsafe { input_bytes(data.cast(), len, name, allow_empty) }?;
    std::str::from_utf8(bytes)
        .map_err(|error| TavError::invalid_argument(format!("{name} is not valid UTF-8: {error}")))
}

/// Validate that an out-parameter pointer is non-null.
///
/// # Safety
/// `out` must be a valid pointer to writable storage, or null.
#[cfg(not(target_family = "wasm"))]
pub unsafe fn out_ptr<T>(out: *mut T, name: &str) -> Result<(), TavError> {
    if out.is_null() {
        return Err(TavError::invalid_argument(format!(
            "{name} pointer is null"
        )));
    }
    Ok(())
}

/// Validate and reset an owned-handle out-parameter to null before fallible work.
///
/// # Safety
/// `out` must be a valid pointer to a writable handle slot, or null.
#[cfg(not(target_family = "wasm"))]
pub unsafe fn owned_out_ptr<T>(out: *mut *mut T, name: &str) -> Result<(), TavError> {
    unsafe { out_ptr(out, name) }?;
    unsafe {
        *out = std::ptr::null_mut();
    }
    Ok(())
}
