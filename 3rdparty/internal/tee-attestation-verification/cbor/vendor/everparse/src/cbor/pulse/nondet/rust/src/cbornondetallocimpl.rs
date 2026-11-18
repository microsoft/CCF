//! Hand-written, trusted implementation of the allocator interface
//! `CBOR.Pulse.API.Nondet.Rust.Alloc` (in `lib/everparse/cbor/pulse`),
//! used by the verified `cbor_nondet_parse_bounded_{sort,hash}_alloc`
//! to allocate their scratch spaces once per call.
//!
//! Specification (trusted): `cbor_nondet_alloc_T(n)` returns either
//! `None`, or `Some(s)` where `s` is a fresh slice of exactly `n`
//! elements, which must be passed exactly once to
//! `cbor_nondet_free_T`, and not used afterwards. The verified callers
//! guarantee this.
//!
//! KaRaMeL extracts calls to these functions as
//! `crate::cbornondetalloc::...` (because of the `rename-prefix`
//! attribute of the `CBOR.Pulse.API.Nondet.Rust.Alloc` bundle), and
//! the option types of their results into the extracted
//! `cbornondetalloc.rs`, which `lib.rs` mounts as
//! `cbornondetalloctypes`. Hence this module, mounted as
//! `cbornondetalloc`, re-exports those types.

pub use crate::cbornondetalloctypes::*;

/// Allocates a zero-initialized slice of `n` elements, without aborting
/// on allocation failure. The slice is leaked, so that the verified
/// caller, which owns it, can free it explicitly.
fn alloc<T: Copy + Default>(n: u64) -> Option<&'static mut [T]> {
    let n = usize::try_from(n).ok()?;
    let mut v: Vec<T> = Vec::new();
    v.try_reserve_exact(n).ok()?;
    v.resize(n, T::default());
    Some(Box::leak(v.into_boxed_slice()))
}

/// Frees a slice returned by `alloc`. This takes a raw pointer rather
/// than a `&mut [T]`: deallocating memory still borrowed by a reference
/// function argument would be undefined behavior (such references are
/// "protected" for the duration of the call.) The verified callers pass
/// a `&mut [T]`, which implicitly coerces to `*mut [T]`.
///
/// # Safety
///
/// `s` must be exactly a slice returned by `alloc` (same pointer and
/// length), not yet freed, and not used afterwards.
unsafe fn free<T>(s: *mut [T]) {
    drop(unsafe { Box::from_raw(s) });
}

pub(crate) fn cbor_nondet_alloc_usize<'a>(n: u64) -> option__Pulse_Lib_Slice_slice·size_t<'a> {
    match alloc(n) {
        None => option__Pulse_Lib_Slice_slice·size_t::None,
        Some(v) => option__Pulse_Lib_Slice_slice·size_t::Some { v },
    }
}

pub(crate) fn cbor_nondet_free_usize(s: *mut [usize]) {
    // SAFETY: see the specification at the top of this module.
    unsafe { free(s) }
}

pub(crate) fn cbor_nondet_alloc_u64<'a>(n: u64) -> option__Pulse_Lib_Slice_slice·uint64_t<'a> {
    match alloc(n) {
        None => option__Pulse_Lib_Slice_slice·uint64_t::None,
        Some(v) => option__Pulse_Lib_Slice_slice·uint64_t::Some { v },
    }
}

pub(crate) fn cbor_nondet_free_u64(s: *mut [u64]) {
    // SAFETY: see the specification at the top of this module.
    unsafe { free(s) }
}
