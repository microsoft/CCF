// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Handle-based C ABI for building, serializing, parsing and inspecting CBOR
//! documents.
//!
//! The public ABI is declared in `include/tav/cbor.h`. The C++ RAII wrapper
//! in `include/tav/cbor.hpp` preserves the same borrowing contract.
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
//! Parsing and serialization reject nesting deeper than the depth the caller
//! asks for, and deeper than [`MAX_DEPTH_LIMIT`], the hard cap, whatever that
//! depth is. Non-deterministic parsing also rejects maps with more than
//! [`cbor::MAX_CBOR_MAP_ENTRIES`] entries and maps inside map keys. Builders
//! do not enforce these limits. Callers must bound the depth they build.
//! Copying, materializing, or dropping an extremely deep value can exhaust
//! the process stack and abort.
//!
//! The default depth, [`cbor::MAX_CBOR_NESTING_DEPTH`], is recommended for
//! untrusted input. No parser bounds the input length, so callers bound the
//! length of untrusted input. A larger depth makes it more expensive to
//! parse, so callers should not raise it for untrusted input: parsing can
//! cost time proportional to the depth limit times the input length, and
//! each non-deterministic parse allocates scratch sized by the depth limit,
//! whatever the input length.

use std::borrow::Cow;
use std::collections::HashSet;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use cbor::{CborValue, Det, Mode, Nondet};

use crate::cbor_view::{CborView, NativeCborValue};

use super::utils::{owned_out_ptr, TavByteBuffer};
use crate::{into_result, TavError, TavErrorCode};

/// A null or otherwise unreadable handle.
pub const KIND_INVALID: i32 = -1;
pub const KIND_SIGNED: i32 = 0;
pub const KIND_BYTES: i32 = 1;
pub const KIND_STRING: i32 = 2;
pub const KIND_ARRAY: i32 = 3;
pub const KIND_MAP: i32 = 4;
pub const KIND_TAGGED: i32 = 5;
pub const KIND_SIMPLE: i32 = 6;

/// Hard cap on the depth a caller may request, bounding recursion in the
/// parser and serializer so that deeply nested input cannot overflow the
/// stack, and how long parsing it can take.
pub const MAX_DEPTH_LIMIT: usize = 64;

/// An opaque, independently owned view into an immutable CBOR document.
pub type TavCborHandle = CborView;

/// Move `value` onto the heap and hand the caller an owning handle.
pub(crate) fn into_handle(value: CborValue<'static>) -> *mut TavCborHandle {
    into_view_handle(CborView::from_native(value))
}

pub(super) fn into_view_handle(view: CborView) -> *mut TavCborHandle {
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
    if data.is_null() || len > isize::MAX as usize {
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
    if slots.is_null() || count > isize::MAX as usize / std::mem::size_of::<*mut TavCborHandle>() {
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

/// Whether `value` is a simple value RFC 8949 reserves.
///
/// The reserved range has no encoding, so a handle holding one could be
/// inspected but never serialized.
pub(crate) fn is_reserved_simple(value: u8) -> bool {
    (24..=31).contains(&value)
}

// --- C ABI entry points ---

fn cbor_error(code: TavErrorCode) -> TavError {
    let message = match code {
        TavErrorCode::CborDecodeFailed => "CBOR decoding failed",
        TavErrorCode::CborKeyNotFound => "CBOR key or tag not found",
        TavErrorCode::CborOutOfBound => "CBOR index out of bounds",
        TavErrorCode::CborTypeMismatch => "CBOR type mismatch or null argument",
        TavErrorCode::CborEncodeFailed => "CBOR construction or encoding failed",
        _ => unreachable!("not a CBOR error code"),
    };
    TavError::new(code, message)
}

/// Reset the output before running a constructor, including consuming builders.
unsafe fn construct(
    out: *mut *mut TavCborHandle,
    body: impl FnOnce() -> *mut TavCborHandle,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out, "out") }?;
        let value = body();
        if value.is_null() {
            return Err(cbor_error(TavErrorCode::CborEncodeFailed));
        }
        unsafe { *out = value };
        Ok(())
    })
}

// --- Constructors ---

/// Build a signed integer.
///
/// # Safety
/// `out` must be null or a writable handle slot.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_signed(
    value: i64,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe { construct(out, || into_handle(CborValue::Int(value))) }
}

/// Build a CBOR simple value, such as false, true, or null.
///
/// Rejects the values RFC 8949 reserves.
///
/// # Safety
/// `out` must be null or a writable handle slot.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_simple(
    value: u8,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe {
        construct(out, || {
            if is_reserved_simple(value) {
                return std::ptr::null_mut();
            }
            into_handle(CborValue::Simple(value))
        })
    }
}

/// Build a byte string that borrows `data`.
///
/// # Safety
/// `data` must be valid for `len` bytes and outlive the returned handle.
/// `out` must be null or a writable handle slot separate from the input.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_bytes(
    data: *const u8,
    len: usize,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe {
        construct(out, || match borrowed(data, len) {
            Some(payload) => into_handle(bytes_value(payload)),
            None => std::ptr::null_mut(),
        })
    }
}

/// Build a text string that borrows `data`, which must be valid UTF-8.
///
/// # Safety
/// `data` must be valid for `len` bytes and outlive the returned handle.
/// `out` must be null or a writable handle slot separate from the input.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_string(
    data: *const c_char,
    len: usize,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe {
        construct(out, || {
            let Some(payload) = borrowed(data.cast::<u8>(), len) else {
                return std::ptr::null_mut();
            };
            match string_value(payload) {
                Some(value) => into_handle(value),
                None => std::ptr::null_mut(),
            }
        })
    }
}

/// Build an array, consuming `count` handles.
///
/// # Safety
/// `items` must be valid for `count` handle variables.
/// `out` must be null or a writable handle slot separate from the input slots.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_array(
    items: *mut *mut TavCborHandle,
    count: usize,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe {
        construct(out, || match take_all(items, count) {
            Some(values) => into_handle(CborValue::Array(values)),
            None => std::ptr::null_mut(),
        })
    }
}

/// Build a map, consuming `2 * pair_count` handles ordered key, value, key, value.
///
/// Keys may be any supported CBOR value. Duplicate keys fail during serialization.
///
/// # Safety
/// `pairs` must be valid for `2 * pair_count` handle variables.
/// `out` must be null or a writable handle slot separate from the input slots.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_map(
    pairs: *mut *mut TavCborHandle,
    pair_count: usize,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe {
        construct(out, || {
            let Some(total) = pair_count.checked_mul(2) else {
                return std::ptr::null_mut();
            };
            let Some(values) = take_all(pairs, total) else {
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
}

/// Build a tagged value, consuming the payload handle.
///
/// # Safety
/// `payload` must point to a writable handle variable.
/// `out` must be null or a writable handle slot separate from `payload`.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_make_tagged(
    tag: u64,
    payload: *mut *mut TavCborHandle,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe {
        construct(out, || match take(payload) {
            Some(value) => into_handle(CborValue::Tagged {
                tag,
                payload: Box::new(value),
            }),
            None => std::ptr::null_mut(),
        })
    }
}

/// Copy a value and everything below it.
///
/// Each payload keeps the ownership the source had: a borrowed payload is
/// borrowed again from the same buffer, and an owned payload is copied.
///
/// # Safety
/// `value` must be null or a live handle.
/// `out` must be null or a writable handle slot separate from the input.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_shallow_copy(
    value: *const TavCborHandle,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe {
        construct(out, || match as_handle(value) {
            Some(value) => into_handle(value.as_native().clone()),
            None => std::ptr::null_mut(),
        })
    }
}

/// Copy a value and everything below it, copying every payload.
///
/// The result borrows nothing, so it outlives the buffers the source was
/// built over.
///
/// # Safety
/// `value` must be null or a live handle.
/// `out` must be null or a writable handle slot separate from the input.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_deep_copy(
    value: *const TavCborHandle,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    unsafe {
        construct(out, || match as_handle(value) {
            Some(value) => into_handle(value.as_native().clone().into_owned()),
            None => std::ptr::null_mut(),
        })
    }
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
    out: *mut *mut TavByteBuffer,
) -> Result<(), TavError> {
    unsafe { owned_out_ptr(out, "out") }?;
    let handle = unsafe { as_handle(value) }
        .ok_or_else(|| TavError::new(TavErrorCode::CborEncodeFailed, "Null CBOR handle"))?;
    let bytes = handle
        .as_native()
        .to_bytes_with_depth::<M>(capped(max_depth))
        .map_err(|e| TavError::new(TavErrorCode::CborEncodeFailed, e))?;
    unsafe { *out = Box::into_raw(TavByteBuffer::from_bytes(bytes)) };
    Ok(())
}

/// Serialize into an owned buffer, released with `tav_byte_buffer_free`.
///
/// # Safety
/// `value` must be null or live. `out` must be null or a writable buffer slot.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_nondet_serialize(
    value: *const TavCborHandle,
    max_depth: usize,
    out: *mut *mut TavByteBuffer,
) -> *mut TavError {
    into_result(|| unsafe { serialize::<Nondet>(value, max_depth, out) })
}

/// Serialize with deterministic encoding.
///
/// # Safety
/// Same requirements as `tav_cbor_nondet_serialize`.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_det_serialize(
    value: *const TavCborHandle,
    max_depth: usize,
    out: *mut *mut TavByteBuffer,
) -> *mut TavError {
    into_result(|| unsafe { serialize::<Det>(value, max_depth, out) })
}

// --- Parsing ---

unsafe fn parse<M: Mode>(
    data: *const u8,
    len: usize,
    max_depth: usize,
    out: *mut *mut TavCborHandle,
) -> Result<(), TavError> {
    unsafe { owned_out_ptr(out, "out") }?;
    let bytes = unsafe { borrowed(data, len) }.ok_or_else(|| {
        TavError::new(TavErrorCode::CborDecodeFailed, "Invalid CBOR input buffer")
    })?;
    let value = CborValue::parse_with_depth::<M>(bytes, capped(max_depth))
        .map_err(|e| TavError::new(TavErrorCode::CborDecodeFailed, e))?;
    unsafe { *out = into_handle(value) };
    Ok(())
}

/// Parse a complete document, borrowing byte and text payloads from `data`.
///
/// Indefinite-length encodings, maps with more than
/// [`cbor::MAX_CBOR_MAP_ENTRIES`] entries, and maps inside map keys are
/// rejected. Keys use RFC 8949 equivalence.
///
/// Each call allocates and zeroes
/// `3 * (max_depth + 1) * cbor::MAX_CBOR_MAP_ENTRIES` words of scratch,
/// whatever the input length.
///
/// # Safety
/// `data` must be valid for `len` bytes and remain alive and unmodified while
/// any derived handle is used. `out` must be null or a writable handle slot.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_nondet_parse(
    data: *const u8,
    len: usize,
    max_depth: usize,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    into_result(|| unsafe { parse::<Nondet>(data, len, max_depth, out) })
}

/// Parse, requiring deterministic encoding.
///
/// # Safety
/// Same requirements as `tav_cbor_nondet_parse`.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_det_parse(
    data: *const u8,
    len: usize,
    max_depth: usize,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    into_result(|| unsafe { parse::<Det>(data, len, max_depth, out) })
}

// --- Inspection ---

unsafe fn read<'a, T>(
    value: *const TavCborHandle,
    reader: impl FnOnce(&'a NativeCborValue) -> Option<T>,
) -> Result<T, TavError> {
    let handle =
        unsafe { as_handle(value) }.ok_or_else(|| cbor_error(TavErrorCode::CborTypeMismatch))?;
    reader(handle.as_native()).ok_or_else(|| cbor_error(TavErrorCode::CborTypeMismatch))
}

/// Report the kind of `value`, or `KIND_INVALID` for a null handle.
///
/// # Safety
/// `value` must be null or a live handle.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_kind(value: *const TavCborHandle) -> i32 {
    catch_unwind(AssertUnwindSafe(|| match unsafe { as_handle(value) } {
        Some(value) => kind_of(value.as_native()),
        None => KIND_INVALID,
    }))
    .unwrap_or(KIND_INVALID)
}

/// Read a signed integer.
///
/// # Safety
/// `value` must be null or a live handle, and `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_as_signed(
    value: *const TavCborHandle,
    out: *mut i64,
) -> *mut TavError {
    into_result(|| {
        if out.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        unsafe {
            *out = read(value, |value| match value {
                CborValue::Int(value) => Some(*value),
                _ => None,
            })?;
        }
        Ok(())
    })
}

/// Read a simple value.
///
/// # Safety
/// `value` must be null or a live handle, and `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_as_simple(
    value: *const TavCborHandle,
    out: *mut u8,
) -> *mut TavError {
    into_result(|| {
        if out.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        unsafe {
            *out = read(value, |value| match value {
                CborValue::Simple(value) => Some(*value),
                _ => None,
            })?;
        }
        Ok(())
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
) -> *mut TavError {
    into_result(|| {
        if out.is_null() || out_len.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        let payload = unsafe {
            read(value, |value| match value {
                CborValue::ByteString(value) => Some(value.as_ref()),
                _ => None,
            })
        }?;
        unsafe {
            *out = payload.as_ptr();
            *out_len = payload.len();
        }
        Ok(())
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
) -> *mut TavError {
    into_result(|| {
        if out.is_null() || out_len.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        let payload = unsafe {
            read(value, |value| match value {
                CborValue::TextString(value) => Some(value.as_ref()),
                _ => None,
            })
        }?;
        unsafe {
            *out = payload.as_ptr().cast();
            *out_len = payload.len();
        }
        Ok(())
    })
}

/// Read the tag of a tagged value.
///
/// # Safety
/// `value` must be null or a live handle, and `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_as_tag(
    value: *const TavCborHandle,
    out: *mut u64,
) -> *mut TavError {
    into_result(|| {
        if out.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        let tag = unsafe {
            read(value, |value| match value {
                CborValue::Tagged { tag, .. } => Some(*tag),
                _ => None,
            })
        }?;
        unsafe { *out = tag };
        Ok(())
    })
}

/// Read the entry count of an array or map.
///
/// # Safety
/// `value` must be null or a live handle, and `out` valid for writing.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_size(
    value: *const TavCborHandle,
    out: *mut usize,
) -> *mut TavError {
    into_result(|| {
        if out.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        let count = unsafe { read(value, |value| value.len().ok()) }?;
        unsafe { *out = count };
        Ok(())
    })
}

// --- Navigation ---

fn project_handle(
    handle: &TavCborHandle,
    project: impl for<'a> FnOnce(&'a NativeCborValue) -> Result<[&'a NativeCborValue; 1], TavError>,
) -> Result<*mut TavCborHandle, TavError> {
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
) -> *mut TavError {
    into_result(|| {
        if out.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        unsafe { *out = std::ptr::null_mut() };
        let Some(handle) = (unsafe { as_handle(value) }) else {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        };
        match project_handle(handle, |value| match value {
            CborValue::Array(_) => value
                .array_at(index)
                .map(|item| [item])
                .map_err(|_| cbor_error(TavErrorCode::CborOutOfBound)),
            _ => Err(cbor_error(TavErrorCode::CborTypeMismatch)),
        }) {
            Ok(projected) => {
                unsafe { *out = projected };
                Ok(())
            }
            Err(error) => Err(error),
        }
    })
}

/// Return an independently owned map value by key.
///
/// Keys use RFC 8949 equivalence, including order-independent map comparison.
///
/// # Safety
/// `value` and `key` must be null or live handles. `out` must point to a null
/// handle slot and must not alias a slot that holds either input handle.
#[no_mangle]
pub unsafe extern "C" fn tav_cbor_map_at(
    value: *const TavCborHandle,
    key: *const TavCborHandle,
    out: *mut *mut TavCborHandle,
) -> *mut TavError {
    into_result(|| {
        if out.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        unsafe { *out = std::ptr::null_mut() };
        let Some(handle) = (unsafe { as_handle(value) }) else {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        };
        let Some(key) = (unsafe { as_handle(key) }) else {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        };
        let key = key.as_native();
        match project_handle(handle, |value| match value {
            CborValue::Map(_) => value
                .map_at(key)
                .map(|found| [found])
                .map_err(|_| cbor_error(TavErrorCode::CborKeyNotFound)),
            _ => Err(cbor_error(TavErrorCode::CborTypeMismatch)),
        }) {
            Ok(projected) => {
                unsafe { *out = projected };
                Ok(())
            }
            Err(error) => Err(error),
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
) -> *mut TavError {
    into_result(|| {
        if out.is_null() {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        }
        unsafe { *out = std::ptr::null_mut() };
        let Some(handle) = (unsafe { as_handle(value) }) else {
            return Err(cbor_error(TavErrorCode::CborTypeMismatch));
        };
        match project_handle(handle, |value| match value {
            CborValue::Tagged {
                tag: actual,
                payload,
            } if *actual == tag => Ok([payload.as_ref()]),
            CborValue::Tagged { .. } => Err(cbor_error(TavErrorCode::CborKeyNotFound)),
            _ => Err(cbor_error(TavErrorCode::CborTypeMismatch)),
        }) {
            Ok(projected) => {
                unsafe { *out = projected };
                Ok(())
            }
            Err(error) => Err(error),
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
) -> *mut TavError {
    into_result(|| unsafe { cbor_map_entry_at(value, index, out, true) })
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
) -> *mut TavError {
    into_result(|| unsafe { cbor_map_entry_at(value, index, out, false) })
}

unsafe fn cbor_map_entry_at(
    value: *const TavCborHandle,
    index: usize,
    out: *mut *mut TavCborHandle,
    want_key: bool,
) -> Result<(), TavError> {
    if out.is_null() {
        return Err(cbor_error(TavErrorCode::CborTypeMismatch));
    }
    unsafe { *out = std::ptr::null_mut() };
    let Some(handle) = (unsafe { as_handle(value) }) else {
        return Err(cbor_error(TavErrorCode::CborTypeMismatch));
    };
    match project_handle(handle, |value| match value {
        CborValue::Map(entries) => entries
            .get(index)
            .map(|(key, item)| [if want_key { key } else { item }])
            .ok_or_else(|| cbor_error(TavErrorCode::CborOutOfBound)),
        _ => Err(cbor_error(TavErrorCode::CborTypeMismatch)),
    }) {
        Ok(projected) => {
            unsafe { *out = projected };
            Ok(())
        }
        Err(error) => Err(error),
    }
}
