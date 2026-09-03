// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Handle-based C ABI for building, serializing, parsing and inspecting CBOR
//! documents.
//!
//! Consumers use the C++ wrapper in `include/tav/cbor.hpp`, which owns
//! the handles and so upholds the contract below. The ABI itself is declared
//! in `include/tav/internal/cbor_abi.h`.
//!
//! # Handle ownership
//!
//! Every handle is independently owned and keeps its complete immutable CBOR
//! document alive. Navigation returns a new owning handle projected into the
//! same document. Container constructors consume the handles they are given,
//! null the caller's variables, and materialize each selected subtree.
//!
//! # Payload ownership
//!
//! Scalars are copied. Byte and text payloads are borrowed: a handle stores
//! the caller's pointer and length. The `'static` in [`TavCborHandle`] is a
//! claim the caller upholds, since a C handle has no lifetime to name.
//! Buffers passed to a constructor or a parse call must remain alive and
//! unmodified while any handle derived from them is in use.
//!
//! # Limits
//!
//! Parsing and serialization reject nesting deeper than [`MAX_DEPTH_LIMIT`],
//! whatever depth the caller asks for. Builders do not enforce this limit.
//! Callers must bound the depth they build. Copying, materializing, or dropping
//! an extremely deep value can exhaust the process stack and abort.

use std::borrow::Cow;
use std::collections::HashSet;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use cbor::{CborValue, Det, Mode, Nondet};

use crate::cbor_view::{CborView, NativeCborValue};

/// Success.
pub const STATUS_OK: i32 = 0;
/// Malformed input, or a panic while parsing.
pub const STATUS_DECODE_FAILED: i32 = 1;
/// A map key or tag that is not present.
pub const STATUS_KEY_NOT_FOUND: i32 = 2;
/// An index past the end of an array or map.
pub const STATUS_OUT_OF_BOUND: i32 = 3;
/// An operation applied to the wrong kind of value.
pub const STATUS_TYPE_MISMATCH: i32 = 4;
/// An unencodable value, or a panic while serializing.
pub const STATUS_ENCODE_FAILED: i32 = 5;

/// A null or otherwise unreadable handle.
pub const KIND_INVALID: i32 = -1;
pub const KIND_SIGNED: i32 = 0;
pub const KIND_BYTES: i32 = 1;
pub const KIND_STRING: i32 = 2;
pub const KIND_ARRAY: i32 = 3;
pub const KIND_MAP: i32 = 4;
pub const KIND_TAGGED: i32 = 5;
pub const KIND_SIMPLE: i32 = 6;

/// Ceiling on the depth a caller may request, bounding recursion in the
/// parser and serializer so that deeply nested input cannot overflow the
/// stack.
pub const MAX_DEPTH_LIMIT: usize = 256;

/// An opaque, independently owned view into an immutable CBOR document.
pub type TavCborHandle = CborView;

/// Move `value` onto the heap and hand the caller an owning handle.
pub(crate) fn into_handle(value: CborValue<'static>) -> *mut TavCborHandle {
    into_view_handle(CborView::from_native(value))
}

fn into_view_handle(view: CborView) -> *mut TavCborHandle {
    Box::into_raw(Box::new(view))
}

/// Read a handle without taking ownership.
///
/// # Safety
/// `handle` must be null or a live handle.
unsafe fn as_handle<'a>(handle: *const TavCborHandle) -> Option<&'a TavCborHandle> {
    unsafe { handle.as_ref() }
}

/// View caller memory as a slice that outlives this call.
///
/// # Safety
/// `data` must be valid for `len` bytes, and that memory must stay alive and
/// unmodified for as long as any handle built from it is used.
pub(crate) unsafe fn borrowed(data: *const u8, len: usize) -> Option<&'static [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if data.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(data, len) })
}

/// Take ownership of the handle in `slot`, leaving null behind.
///
/// # Safety
/// `slot` must be null or point to a writable handle variable.
pub(crate) unsafe fn take(slot: *mut *mut TavCborHandle) -> Option<CborValue<'static>> {
    if slot.is_null() {
        return None;
    }
    let handle = unsafe { *slot };
    if handle.is_null() {
        return None;
    }
    unsafe { *slot = std::ptr::null_mut() };
    let view = *unsafe { Box::from_raw(handle) };
    Some(view.into_native())
}

/// Take ownership of `count` distinct handles.
///
/// # Safety
/// `slots` must be valid for `count` handle variables holding distinct
/// handles.
pub(crate) unsafe fn take_all(
    slots: *mut *mut TavCborHandle,
    count: usize,
) -> Option<Vec<CborValue<'static>>> {
    if count == 0 {
        return Some(Vec::new());
    }
    if slots.is_null() {
        return None;
    }

    let slots_slice = unsafe { std::slice::from_raw_parts_mut(slots, count) };
    let mut distinct = HashSet::with_capacity(count);
    for &handle in slots_slice.iter() {
        if handle.is_null() || !distinct.insert(handle) {
            return None;
        }
    }

    let views = slots_slice
        .iter_mut()
        .map(|slot| {
            let handle = std::mem::replace(slot, std::ptr::null_mut());
            *unsafe { Box::from_raw(handle) }
        })
        .collect::<Vec<_>>();
    Some(views.into_iter().map(CborView::into_native).collect())
}

/// Build a byte string that borrows `payload`.
pub(crate) fn bytes_value(payload: &'static [u8]) -> CborValue<'static> {
    CborValue::ByteString(Cow::Borrowed(payload))
}

/// Build a text string that borrows `payload`, rejecting invalid UTF-8.
pub(crate) fn string_value(payload: &'static [u8]) -> Option<CborValue<'static>> {
    std::str::from_utf8(payload)
        .ok()
        .map(|text| CborValue::TextString(Cow::Borrowed(text)))
}

/// Clamp a caller-supplied depth to [`MAX_DEPTH_LIMIT`].
pub(crate) fn capped(max_depth: usize) -> usize {
    max_depth.min(MAX_DEPTH_LIMIT)
}

/// Report the kind of `value` as one of the `KIND_*` constants.
pub(crate) fn kind_of(value: &CborValue<'static>) -> i32 {
    match value {
        CborValue::Int(_) => KIND_SIGNED,
        CborValue::ByteString(_) => KIND_BYTES,
        CborValue::TextString(_) => KIND_STRING,
        CborValue::Array(_) => KIND_ARRAY,
        CborValue::Map(_) => KIND_MAP,
        CborValue::Tagged { .. } => KIND_TAGGED,
        CborValue::Simple(_) => KIND_SIMPLE,
    }
}

/// Whether `value` may be used as a map key.
///
/// Containers are excluded, so that every key a map can hold is also a key
/// the C ABI can look up. Parsing enforces the same rule, so a map reached
/// through this ABI never holds a key that map_at would refuse.
pub(crate) fn usable_as_key(value: &CborValue<'static>) -> bool {
    !matches!(
        value,
        CborValue::Array(_) | CborValue::Map(_) | CborValue::Tagged { .. }
    )
}

/// Whether every map below `value` keys its entries on something usable.
///
/// Recursion is bounded by the depth the parse was capped to.
pub(crate) fn keys_are_usable(value: &CborValue<'static>) -> bool {
    match value {
        CborValue::Array(items) => items.iter().all(keys_are_usable),
        CborValue::Map(entries) => entries
            .iter()
            .all(|(key, item)| usable_as_key(key) && keys_are_usable(item)),
        CborValue::Tagged { payload, .. } => keys_are_usable(payload),
        _ => true,
    }
}

/// Whether `value` is a simple value RFC 8949 reserves.
///
/// The reserved range has no encoding, so a handle holding one could be
/// inspected but never serialized.
pub(crate) fn is_reserved_simple(value: u8) -> bool {
    (24..=31).contains(&value)
}

// --- C ABI entry points ---
//
// Every entry point runs its body under `std::panic::catch_unwind`, so a
// panic is reported as a status code or a null handle rather than unwinding
// into a C frame, which would abort the host process.

/// Run `body`, returning a null handle if it panics.
fn guard_handle(body: impl FnOnce() -> *mut TavCborHandle) -> *mut TavCborHandle {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(std::ptr::null_mut())
}

/// Run `body`, returning `on_panic` if it panics.
fn guard_status(on_panic: i32, body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(on_panic)
}

/// Validate and reset a scalar out-parameter before fallible work.
///
/// # Safety
/// `out` must be null or valid for writing.
unsafe fn reset_scalar_out<T: Default>(out: *mut T) -> bool {
    if out.is_null() {
        return false;
    }
    unsafe { *out = T::default() };
    true
}

/// Validate and reset an owned-pointer out-parameter before fallible work.
///
/// # Safety
/// `out` must be null or valid for writing.
unsafe fn reset_owned_out<T>(out: *mut *mut T) -> bool {
    if out.is_null() {
        return false;
    }
    unsafe { *out = std::ptr::null_mut() };
    true
}

/// Reset the error out-parameters, which the caller may omit.
///
/// # Safety
/// `err_ptr` and `err_len` must be null or valid for writing.
unsafe fn reset_error(err_ptr: *mut *mut u8, err_len: *mut usize) {
    unsafe {
        reset_owned_out(err_ptr);
        reset_scalar_out(err_len);
    }
}

/// Copy `msg` into a caller-owned buffer, released with [`tav_cbor_buffer_free`].
///
/// # Safety
/// `err_ptr` and `err_len` must be null or valid for writing.
unsafe fn set_error(msg: &str, err_ptr: *mut *mut u8, err_len: *mut usize) {
    if err_ptr.is_null() || err_len.is_null() {
        return;
    }
    let bytes = msg.as_bytes().to_vec().into_boxed_slice();
    let len = bytes.len();
    let ptr = Box::into_raw(bytes).cast::<u8>();
    unsafe {
        *err_ptr = ptr;
        *err_len = len;
    }
}

// --- Constructors ---

/// Build a signed integer.
#[no_mangle]
pub extern "C" fn tav_cbor_make_signed(value: i64) -> *mut TavCborHandle {
    guard_handle(|| into_handle(CborValue::Int(value)))
}

/// Build a CBOR simple value, such as false, true, or null.
///
/// Returns null for the values RFC 8949 reserves.
#[no_mangle]
pub extern "C" fn tav_cbor_make_simple(value: u8) -> *mut TavCborHandle {
    guard_handle(|| {
        if is_reserved_simple(value) {
            return std::ptr::null_mut();
        }
        into_handle(CborValue::Simple(value))
    })
}

/// Build a byte string that borrows `data`.
///
/// # Safety
/// `data` must be valid for `len` bytes and outlive the returned handle.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_bytes(data: *const u8, len: usize) -> *mut TavCborHandle {
    guard_handle(|| match unsafe { borrowed(data, len) } {
        Some(payload) => into_handle(bytes_value(payload)),
        None => std::ptr::null_mut(),
    })
}

/// Build a text string that borrows `data`, which must be valid UTF-8.
///
/// # Safety
/// `data` must be valid for `len` bytes and outlive the returned handle.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_string(
    data: *const c_char,
    len: usize,
) -> *mut TavCborHandle {
    guard_handle(|| {
        let Some(payload) = (unsafe { borrowed(data.cast::<u8>(), len) }) else {
            return std::ptr::null_mut();
        };
        match string_value(payload) {
            Some(value) => into_handle(value),
            None => std::ptr::null_mut(),
        }
    })
}

/// Build an array, consuming `count` handles.
///
/// # Safety
/// `items` must be valid for `count` handle variables.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_array(
    items: *mut *mut TavCborHandle,
    count: usize,
) -> *mut TavCborHandle {
    guard_handle(|| match unsafe { take_all(items, count) } {
        Some(values) => into_handle(CborValue::Array(values)),
        None => std::ptr::null_mut(),
    })
}

/// Build a map, consuming `2 * pair_count` handles ordered key, value, key, value.
///
/// Keys must not be arrays, maps or tagged values, matching the lookup
/// [`tav_cbor_map_at`] offers. Invalid keys are rejected without consuming any
/// handles. Duplicate keys are unsupported and fail during serialization.
///
/// # Safety
/// `pairs` must be valid for `2 * pair_count` handle variables.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_map(
    pairs: *mut *mut TavCborHandle,
    pair_count: usize,
) -> *mut TavCborHandle {
    guard_handle(|| {
        let Some(total) = pair_count.checked_mul(2) else {
            return std::ptr::null_mut();
        };
        if total != 0 && pairs.is_null() {
            return std::ptr::null_mut();
        }
        let pairs_slice = if total == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(pairs, total) }
        };
        for pair in pairs_slice.chunks_exact(2) {
            let Some(key) = (unsafe { as_handle(pair[0]) }) else {
                return std::ptr::null_mut();
            };
            if !usable_as_key(key.as_native()) {
                return std::ptr::null_mut();
            }
        }

        let Some(values) = (unsafe { take_all(pairs, total) }) else {
            return std::ptr::null_mut();
        };
        let mut entries = Vec::with_capacity(pair_count);
        let mut it = values.into_iter();
        while let (Some(key), Some(value)) = (it.next(), it.next()) {
            entries.push((key, value));
        }
        into_handle(CborValue::Map(entries))
    })
}

/// Build a tagged value, consuming the payload handle.
///
/// # Safety
/// `payload` must point to a writable handle variable.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_tagged(
    tag: u64,
    payload: *mut *mut TavCborHandle,
) -> *mut TavCborHandle {
    guard_handle(|| match unsafe { take(payload) } {
        Some(value) => into_handle(CborValue::Tagged {
            tag,
            payload: Box::new(value),
        }),
        None => std::ptr::null_mut(),
    })
}

/// Copy a value and everything below it.
///
/// Each payload keeps the ownership the source had: a borrowed payload is
/// borrowed again from the same buffer, and an owned payload is copied.
///
/// # Safety
/// `value` must be null or a live handle.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_shallow_copy(value: *const TavCborHandle) -> *mut TavCborHandle {
    guard_handle(|| match unsafe { as_handle(value) } {
        Some(value) => into_handle(value.as_native().clone()),
        None => std::ptr::null_mut(),
    })
}

/// Copy a value and everything below it, copying every payload.
///
/// The result borrows nothing, so it outlives the buffers the source was
/// built over.
///
/// # Safety
/// `value` must be null or a live handle.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_deep_copy(value: *const TavCborHandle) -> *mut TavCborHandle {
    guard_handle(|| match unsafe { as_handle(value) } {
        Some(value) => into_handle(value.as_native().clone().into_owned()),
        None => std::ptr::null_mut(),
    })
}

/// Release an owning handle. Freeing null is a no-op.
///
/// # Safety
/// `value` must be null or a live handle returned by this API, and must not
/// have been released already.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_free(value: *mut TavCborHandle) {
    if value.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(value) })));
}

// --- Serialization ---

unsafe fn serialize<M: Mode>(
    value: *const TavCborHandle,
    max_depth: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    unsafe { reset_error(err_ptr, err_len) };
    let out_ok = unsafe { reset_owned_out(out_ptr) };
    let len_ok = unsafe { reset_scalar_out(out_len) };
    let Some(handle) = (unsafe { as_handle(value) }) else {
        unsafe { set_error("Null CBOR handle", err_ptr, err_len) };
        return STATUS_ENCODE_FAILED;
    };
    if !out_ok || !len_ok {
        unsafe { set_error("Null output pointer", err_ptr, err_len) };
        return STATUS_ENCODE_FAILED;
    }
    match handle
        .as_native()
        .to_bytes_with_depth::<M>(capped(max_depth))
    {
        Ok(bytes) => {
            let bytes = bytes.into_boxed_slice();
            let len = bytes.len();
            let ptr = Box::into_raw(bytes).cast::<u8>();
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            STATUS_OK
        }
        Err(e) => {
            unsafe { set_error(&e, err_ptr, err_len) };
            STATUS_ENCODE_FAILED
        }
    }
}

/// Serialize.
///
/// The buffer and message outputs are cleared before any work, so a failure
/// leaves no stale pointer to free. On success writes an owned buffer through
/// `out_ptr`/`out_len`, released with [`tav_cbor_buffer_free`]. On failure
/// writes a UTF-8 message, not NUL terminated, through `err_ptr`/`err_len`,
/// released the same way.
///
/// # Safety
/// All output pointers must be null or valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_nondet_serialize(
    value: *const TavCborHandle,
    max_depth: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    guard_status(STATUS_ENCODE_FAILED, || unsafe {
        serialize::<Nondet>(value, max_depth, out_ptr, out_len, err_ptr, err_len)
    })
}

/// Serialize with deterministic encoding.
///
/// # Safety
/// All output pointers must be null or valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_det_serialize(
    value: *const TavCborHandle,
    max_depth: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    guard_status(STATUS_ENCODE_FAILED, || unsafe {
        serialize::<Det>(value, max_depth, out_ptr, out_len, err_ptr, err_len)
    })
}

// --- Parsing ---

unsafe fn parse<M: Mode>(
    data: *const u8,
    len: usize,
    max_depth: usize,
    out_value: *mut *mut TavCborHandle,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    unsafe { reset_error(err_ptr, err_len) };
    if !unsafe { reset_owned_out(out_value) } {
        unsafe { set_error("Null output pointer", err_ptr, err_len) };
        return STATUS_DECODE_FAILED;
    }
    let Some(bytes) = (unsafe { borrowed(data, len) }) else {
        unsafe { set_error("Null CBOR input", err_ptr, err_len) };
        return STATUS_DECODE_FAILED;
    };
    match CborValue::parse_with_depth::<M>(bytes, capped(max_depth)) {
        Ok(value) => {
            if !keys_are_usable(&value) {
                unsafe { set_error("Container used as a map key", err_ptr, err_len) };
                return STATUS_DECODE_FAILED;
            }
            unsafe { *out_value = into_handle(value) };
            STATUS_OK
        }
        Err(e) => {
            unsafe { set_error(&e, err_ptr, err_len) };
            STATUS_DECODE_FAILED
        }
    }
}

/// Parse.
///
/// Indefinite-length encodings are rejected, and the whole input must be
/// consumed. A document that keys a map entry on a container is rejected too,
/// so a parsed map holds only keys [`tav_cbor_map_at`] can look up. The
/// returned tree borrows byte and text payloads from `data`, which must
/// outlive it. The handle and message outputs are cleared before any work, so
/// a failure leaves no stale handle to free.
///
/// # Safety
/// `data` must be valid for `len` bytes and outlive the returned handle. All
/// output pointers must be null or valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_nondet_parse(
    data: *const u8,
    len: usize,
    max_depth: usize,
    out_value: *mut *mut TavCborHandle,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    guard_status(STATUS_DECODE_FAILED, || unsafe {
        parse::<Nondet>(data, len, max_depth, out_value, err_ptr, err_len)
    })
}

/// Parse, requiring deterministic encoding.
///
/// # Safety
/// `data` must be valid for `len` bytes and outlive the returned handle. All
/// output pointers must be null or valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_det_parse(
    data: *const u8,
    len: usize,
    max_depth: usize,
    out_value: *mut *mut TavCborHandle,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    guard_status(STATUS_DECODE_FAILED, || unsafe {
        parse::<Det>(data, len, max_depth, out_value, err_ptr, err_len)
    })
}

/// Release a buffer or error message. Freeing null is a no-op.
///
/// # Safety
/// `ptr`/`len` must come from a `tav_cbor_*` call and must not have been
/// released already.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_buffer_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

// --- Inspection ---

/// Report the kind of `value`, or `KIND_INVALID` for a null handle.
///
/// # Safety
/// `value` must be null or a live handle.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_kind(value: *const TavCborHandle) -> i32 {
    guard_status(KIND_INVALID, || match unsafe { as_handle(value) } {
        Some(value) => kind_of(value.as_native()),
        None => KIND_INVALID,
    })
}

/// Read a signed integer.
///
/// # Safety
/// `value` must be null or a live handle, and `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_as_signed(value: *const TavCborHandle, out: *mut i64) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        match unsafe { as_handle(value) }.map(CborView::as_native) {
            Some(CborValue::Int(v)) => {
                unsafe { *out = *v };
                STATUS_OK
            }
            _ => STATUS_TYPE_MISMATCH,
        }
    })
}

/// Read a simple value.
///
/// # Safety
/// `value` must be null or a live handle, and `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_as_simple(value: *const TavCborHandle, out: *mut u8) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        match unsafe { as_handle(value) }.map(CborView::as_native) {
            Some(CborValue::Simple(v)) => {
                unsafe { *out = *v };
                STATUS_OK
            }
            _ => STATUS_TYPE_MISMATCH,
        }
    })
}

/// Read a byte string payload, which points into the buffer it borrows.
///
/// # Safety
/// `value` must be null or a live handle, and the outputs valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_as_bytes(
    value: *const TavCborHandle,
    out: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() || out_len.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        match unsafe { as_handle(value) }.map(CborView::as_native) {
            Some(CborValue::ByteString(payload)) => {
                unsafe {
                    *out = payload.as_ptr();
                    *out_len = payload.len();
                }
                STATUS_OK
            }
            _ => STATUS_TYPE_MISMATCH,
        }
    })
}

/// Read a text string payload, which points into the buffer it borrows.
///
/// # Safety
/// `value` must be null or a live handle, and the outputs valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_as_string(
    value: *const TavCborHandle,
    out: *mut *const c_char,
    out_len: *mut usize,
) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() || out_len.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        match unsafe { as_handle(value) }.map(CborView::as_native) {
            Some(CborValue::TextString(payload)) => {
                unsafe {
                    *out = payload.as_ptr().cast();
                    *out_len = payload.len();
                }
                STATUS_OK
            }
            _ => STATUS_TYPE_MISMATCH,
        }
    })
}

/// Read the tag of a tagged value.
///
/// # Safety
/// `value` must be null or a live handle, and `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_as_tag(value: *const TavCborHandle, out: *mut u64) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        match unsafe { as_handle(value) }.map(CborView::as_native) {
            Some(CborValue::Tagged { tag, .. }) => {
                unsafe { *out = *tag };
                STATUS_OK
            }
            _ => STATUS_TYPE_MISMATCH,
        }
    })
}

/// Read the entry count of an array or map.
///
/// # Safety
/// `value` must be null or a live handle, and `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_size(value: *const TavCborHandle, out: *mut usize) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        let count = match unsafe { as_handle(value) }.map(CborView::as_native) {
            Some(CborValue::Array(items)) => items.len(),
            Some(CborValue::Map(entries)) => entries.len(),
            _ => return STATUS_TYPE_MISMATCH,
        };
        unsafe { *out = count };
        STATUS_OK
    })
}

// --- Navigation ---

fn project_handle(
    handle: &TavCborHandle,
    project: impl for<'a> FnOnce(&'a NativeCborValue) -> Result<[&'a NativeCborValue; 1], i32>,
) -> Result<*mut TavCborHandle, i32> {
    handle.project(project).map(|[view]| into_view_handle(view))
}

/// Return an independently owned array element by index.
///
/// # Safety
/// `value` must be null or a live handle. `out` must point to a null handle
/// slot and must not alias a slot that holds `value`.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_array_at(
    value: *const TavCborHandle,
    index: usize,
    out: *mut *mut TavCborHandle,
) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        unsafe { *out = std::ptr::null_mut() };
        let Some(handle) = (unsafe { as_handle(value) }) else {
            return STATUS_TYPE_MISMATCH;
        };
        match project_handle(handle, |value| match value {
            CborValue::Array(items) => items
                .get(index)
                .map(|item| [item])
                .ok_or(STATUS_OUT_OF_BOUND),
            _ => Err(STATUS_TYPE_MISMATCH),
        }) {
            Ok(projected) => {
                unsafe { *out = projected };
                STATUS_OK
            }
            Err(status) => status,
        }
    })
}

/// Return an independently owned map value by key.
///
/// Containers are not usable as keys and are reported as a type mismatch.
///
/// # Safety
/// `value` and `key` must be null or live handles. `out` must point to a null
/// handle slot and must not alias a slot that holds either input handle.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_map_at(
    value: *const TavCborHandle,
    key: *const TavCborHandle,
    out: *mut *mut TavCborHandle,
) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        unsafe { *out = std::ptr::null_mut() };
        let Some(handle) = (unsafe { as_handle(value) }) else {
            return STATUS_TYPE_MISMATCH;
        };
        let Some(key) = (unsafe { as_handle(key) }) else {
            return STATUS_TYPE_MISMATCH;
        };
        let key = key.as_native();
        if !usable_as_key(key) {
            return STATUS_TYPE_MISMATCH;
        }
        match project_handle(handle, |value| match value {
            CborValue::Map(entries) => entries
                .iter()
                .find(|(candidate, _)| candidate == key)
                .map(|(_, found)| [found])
                .ok_or(STATUS_KEY_NOT_FOUND),
            _ => Err(STATUS_TYPE_MISMATCH),
        }) {
            Ok(projected) => {
                unsafe { *out = projected };
                STATUS_OK
            }
            Err(status) => status,
        }
    })
}

/// Return an independently owned tagged payload, checking the tag.
///
/// # Safety
/// `value` must be null or a live handle. `out` must point to a null handle
/// slot and must not alias a slot that holds `value`.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_tag_at(
    value: *const TavCborHandle,
    tag: u64,
    out: *mut *mut TavCborHandle,
) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || {
        if out.is_null() {
            return STATUS_TYPE_MISMATCH;
        }
        unsafe { *out = std::ptr::null_mut() };
        let Some(handle) = (unsafe { as_handle(value) }) else {
            return STATUS_TYPE_MISMATCH;
        };
        match project_handle(handle, |value| match value {
            CborValue::Tagged {
                tag: actual,
                payload,
            } if *actual == tag => Ok([payload]),
            CborValue::Tagged { .. } => Err(STATUS_KEY_NOT_FOUND),
            _ => Err(STATUS_TYPE_MISMATCH),
        }) {
            Ok(projected) => {
                unsafe { *out = projected };
                STATUS_OK
            }
            Err(status) => status,
        }
    })
}

/// Return an independently owned map key by entry index.
///
/// # Safety
/// `value` must be null or a live handle. `out` must point to a null handle
/// slot and must not alias a slot that holds `value`.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_map_key_at(
    value: *const TavCborHandle,
    index: usize,
    out: *mut *mut TavCborHandle,
) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || unsafe {
        cbor_map_entry_at(value, index, out, true)
    })
}

/// Return an independently owned map value by entry index.
///
/// # Safety
/// `value` must be null or a live handle. `out` must point to a null handle
/// slot and must not alias a slot that holds `value`.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_map_value_at(
    value: *const TavCborHandle,
    index: usize,
    out: *mut *mut TavCborHandle,
) -> i32 {
    guard_status(STATUS_TYPE_MISMATCH, || unsafe {
        cbor_map_entry_at(value, index, out, false)
    })
}

unsafe fn cbor_map_entry_at(
    value: *const TavCborHandle,
    index: usize,
    out: *mut *mut TavCborHandle,
    want_key: bool,
) -> i32 {
    if out.is_null() {
        return STATUS_TYPE_MISMATCH;
    }
    unsafe { *out = std::ptr::null_mut() };
    let Some(handle) = (unsafe { as_handle(value) }) else {
        return STATUS_TYPE_MISMATCH;
    };
    match project_handle(handle, |value| match value {
        CborValue::Map(entries) => entries
            .get(index)
            .map(|(key, item)| [if want_key { key } else { item }])
            .ok_or(STATUS_OUT_OF_BOUND),
        _ => Err(STATUS_TYPE_MISMATCH),
    }) {
        Ok(projected) => {
            unsafe { *out = projected };
            STATUS_OK
        }
        Err(status) => status,
    }
}
