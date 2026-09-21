// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR values backed by EverCBOR, in both deterministic and
//! non-deterministic modes.
//!
//! Every entry point is parameterised by a [`Mode`].
//!
//! Parsing: [`Nondet`] accepts well-formed definite-length encodings whose
//! integers fit `i64`. [`Det`] additionally requires RFC 8949 Section 4.2.1
//! canonical form, so it rejects non-preferred head widths and map keys out of
//! canonical order.
//!
//! Serialization: the modes differ only in map entry order. [`Det`] sorts keys
//! into canonical order, [`Nondet`] emits them as given. Both write preferred
//! head widths, so all other bytes are identical.
//!
//! Both modes reject floating-point values, indefinite-length encodings,
//! invalid UTF-8, duplicate map keys, and integers outside the range of
//! `i64`.
//!
//! [`CborValue`] holds its byte and text payloads in [`Cow`], so parsing
//! borrows: string payloads point into the input buffer, which must outlive
//! the value. [`CborValue::into_owned`] detaches a value from its input.
//!
//! Round trips are not byte-preserving. Integers are decoded to `i64`,
//! discarding the width of the original head, so a non-preferred encoding is
//! re-serialized in its preferred form.
//!
//! [`CborValue::from_bytes`] and [`CborValue::to_bytes`] are deprecated. They
//! keep the pre-[`Mode`] behaviour: parse in [`Nondet`] mode into an owned
//! value, and serialize in [`Det`] mode.

use std::borrow::Cow;

/// Default maximum nesting depth for CBOR parse and serialization.
///
/// Depth 0 is the root item. Containers (arrays, maps, and tags) increment the
/// depth of their children, so an empty container is depth 0 like any other
/// leaf. This bounds the recursion depth reached while walking untrusted
/// input.
pub const MAX_CBOR_NESTING_DEPTH: usize = 64;

/// Bound passed to EverCBOR's serialized-size estimator.
const SIZE_BOUND: usize = usize::MAX;

/// Number of child slots to reserve for a container of `declared` length.
///
/// Parsing has already rejected any container whose declared length is not
/// backed by items present in the input, so this is bounded by the input
/// length. A value too large for `usize` cannot be allocated, and is left to
/// fail as the vector grows.
fn reserve_for(declared: u64) -> usize {
    usize::try_from(declared).unwrap_or(0)
}

/// Arena of `Box<[T]>` chunks holding EverCBOR child nodes.
///
/// EverCBOR constructors borrow their children: `mk_array` takes `&'a [Item]`,
/// and `mk_map` takes `&'a mut [MapEntry]` so it can sort in place. Children
/// therefore have to outlive the frame that builds them.
struct SimpleArena<T>(std::cell::RefCell<Vec<Box<[T]>>>);

impl<T> SimpleArena<T> {
    fn new() -> Self {
        Self(std::cell::RefCell::new(Vec::new()))
    }

    // Sound because each call appends a fresh chunk that is never handed out
    // twice, moved, or removed.
    #[allow(clippy::mut_from_ref)]
    fn alloc(&self, val: T) -> &mut T {
        self.alloc_extend(std::iter::once(val)).first_mut().unwrap()
    }

    #[allow(clippy::mut_from_ref)]
    fn alloc_extend(&self, vals: impl IntoIterator<Item = T>) -> &mut [T] {
        let boxed: Box<[T]> = vals.into_iter().collect();
        let mut store = self.0.borrow_mut();
        store.push(boxed);
        let slot = store.last_mut().unwrap();
        // SAFETY: The returned reference borrows `self`, which owns the
        // backing storage. Chunks are never moved or removed, so the
        // reference remains valid for the lifetime of the arena.
        unsafe { &mut *(slot.as_mut() as *mut [T]) }
    }
}

/// One layer of an EverCBOR item, normalised across the two backends.
///
/// Not part of the stable API.
#[doc(hidden)]
pub enum RawView<'a, B> {
    Int64 { negative: bool, magnitude: u64 },
    ByteString(&'a [u8]),
    TextString(&'a str),
    Array(Vec<B>),
    Map(Vec<(B, B)>),
    Tagged { tag: u64, payload: B },
    Simple(u8),
}

/// The operations [`CborValue`] needs from an EverCBOR backend.
///
/// Implemented for the deterministic and non-deterministic item types only.
/// Not part of the stable API.
#[doc(hidden)]
pub trait Backend<'a>: Sized + Copy {
    type MapEntry: Copy;

    fn parse(input: &'a [u8]) -> Option<(Self, &'a [u8])>;
    fn destruct(item: Self) -> RawView<'a, Self>;
    fn to_vec(item: Self) -> Result<Vec<u8>, String>;

    fn mk_int64(negative: bool, magnitude: u64) -> Self;
    fn mk_simple(value: u8) -> Option<Self>;
    fn mk_text(value: &'a str) -> Option<Self>;
    fn mk_bytes(value: &'a [u8]) -> Option<Self>;
    fn mk_tagged(tag: u64, payload: &'a Self) -> Self;
    fn mk_array(items: &'a [Self]) -> Option<Self>;
    fn mk_map_entry(key: Self, value: Self) -> Self::MapEntry;
    fn mk_map(entries: &'a mut [Self::MapEntry]) -> Option<Self>;
}

mod det_backend {
    use super::{reserve_for, Backend, RawView, SimpleArena, SIZE_BOUND};
    use cborrs::cbordet as api;

    /// Serializes into a fresh buffer.
    ///
    /// `item`'s lifetime stays elided: naming it would tie the caller's borrow
    /// to the local buffer.
    fn to_vec(item: api::CborDet) -> Result<Vec<u8>, String> {
        let size = api::cbor_det_size(item, SIZE_BOUND)
            .ok_or("Failed to estimate CBOR serialization size")?;
        let mut buf = vec![0u8; size];
        let written = api::cbor_det_serialize(item, &mut buf).ok_or("Failed to serialize CBOR")?;
        if size != written {
            return Err(format!(
                "CBOR serialize mismatch: written {written} != expected {size}"
            ));
        }
        Ok(buf)
    }

    pub(super) fn value_to_vec(
        value: &super::CborValue<'_>,
        max_depth: usize,
    ) -> Result<Vec<u8>, String> {
        let items: SimpleArena<api::CborDet<'_>> = SimpleArena::new();
        let entries: SimpleArena<api::CborDetMapEntry<'_>> = SimpleArena::new();
        let raw = value.to_raw(&items, &entries, max_depth)?;
        to_vec(raw)
    }

    impl<'a> Backend<'a> for api::CborDet<'a> {
        type MapEntry = api::CborDetMapEntry<'a>;

        fn parse(input: &'a [u8]) -> Option<(Self, &'a [u8])> {
            api::cbor_det_parse(input)
        }

        fn destruct(item: Self) -> RawView<'a, Self> {
            match api::cbor_det_destruct(item) {
                api::CborDetView::Int64 { kind, value } => RawView::Int64 {
                    negative: matches!(kind, api::CborDetIntKind::NegInt64),
                    magnitude: value,
                },
                api::CborDetView::ByteString { payload } => RawView::ByteString(payload),
                api::CborDetView::TextString { payload } => RawView::TextString(payload),
                api::CborDetView::Array { _0: array } => {
                    let mut items =
                        Vec::with_capacity(reserve_for(api::cbor_det_get_array_length(array)));
                    items.extend(array);
                    RawView::Array(items)
                }
                api::CborDetView::Map { _0: map } => {
                    let mut entries =
                        Vec::with_capacity(reserve_for(api::cbor_det_get_map_length(map)));
                    entries.extend(map.into_iter().map(|e| {
                        (
                            api::cbor_det_map_entry_key(e),
                            api::cbor_det_map_entry_value(e),
                        )
                    }));
                    RawView::Map(entries)
                }
                api::CborDetView::Tagged { tag, payload } => RawView::Tagged { tag, payload },
                api::CborDetView::SimpleValue { _0: value } => RawView::Simple(value),
            }
        }

        fn to_vec(item: Self) -> Result<Vec<u8>, String> {
            to_vec(item)
        }

        fn mk_int64(negative: bool, magnitude: u64) -> Self {
            let kind = if negative {
                api::CborDetIntKind::NegInt64
            } else {
                api::CborDetIntKind::UInt64
            };
            api::cbor_det_mk_int64(kind, magnitude)
        }

        fn mk_simple(value: u8) -> Option<Self> {
            api::cbor_det_mk_simple_value(value)
        }

        fn mk_text(value: &'a str) -> Option<Self> {
            api::cbor_det_mk_text_string(value)
        }

        fn mk_bytes(value: &'a [u8]) -> Option<Self> {
            api::cbor_det_mk_byte_string(value)
        }

        fn mk_tagged(tag: u64, payload: &'a Self) -> Self {
            api::cbor_det_mk_tagged(tag, payload)
        }

        fn mk_array(items: &'a [Self]) -> Option<Self> {
            api::cbor_det_mk_array(items)
        }

        fn mk_map_entry(key: Self, value: Self) -> Self::MapEntry {
            api::cbor_det_mk_map_entry(key, value)
        }

        fn mk_map(entries: &'a mut [Self::MapEntry]) -> Option<Self> {
            api::cbor_det_mk_map(entries)
        }
    }
}

mod nondet_backend {
    use super::{reserve_for, Backend, RawView, SimpleArena, SIZE_BOUND};
    use cborrs_nondet::cbornondet as api;

    /// See the deterministic counterpart for the note on the elided lifetime.
    fn to_vec(item: api::CborNondet) -> Result<Vec<u8>, String> {
        let size = api::cbor_nondet_size(item, SIZE_BOUND)
            .ok_or("Failed to estimate CBOR serialization size")?;
        let mut buf = vec![0u8; size];
        let written =
            api::cbor_nondet_serialize(item, &mut buf).ok_or("Failed to serialize CBOR")?;
        if size != written {
            return Err(format!(
                "CBOR serialize mismatch: written {written} != expected {size}"
            ));
        }
        Ok(buf)
    }

    pub(super) fn value_to_vec(
        value: &super::CborValue<'_>,
        max_depth: usize,
    ) -> Result<Vec<u8>, String> {
        let items: SimpleArena<api::CborNondet<'_>> = SimpleArena::new();
        let entries: SimpleArena<api::CborNondetMapEntry<'_>> = SimpleArena::new();
        let raw = value.to_raw(&items, &entries, max_depth)?;
        to_vec(raw)
    }

    impl<'a> Backend<'a> for api::CborNondet<'a> {
        type MapEntry = api::CborNondetMapEntry<'a>;

        fn parse(input: &'a [u8]) -> Option<(Self, &'a [u8])> {
            api::cbor_nondet_parse(None, false, input)
        }

        fn destruct(item: Self) -> RawView<'a, Self> {
            match api::cbor_nondet_destruct(item) {
                api::CborNondetView::Int64 { kind, value } => RawView::Int64 {
                    negative: matches!(kind, api::CborNondetIntKind::NegInt64),
                    magnitude: value,
                },
                api::CborNondetView::ByteString { payload } => RawView::ByteString(payload),
                api::CborNondetView::TextString { payload } => RawView::TextString(payload),
                api::CborNondetView::Array { _0: array } => {
                    let mut items =
                        Vec::with_capacity(reserve_for(api::cbor_nondet_get_array_length(array)));
                    items.extend(array);
                    RawView::Array(items)
                }
                api::CborNondetView::Map { _0: map } => {
                    let mut entries =
                        Vec::with_capacity(reserve_for(api::cbor_nondet_get_map_length(map)));
                    entries.extend(map.into_iter().map(|e| {
                        (
                            api::cbor_nondet_map_entry_key(e),
                            api::cbor_nondet_map_entry_value(e),
                        )
                    }));
                    RawView::Map(entries)
                }
                api::CborNondetView::Tagged { tag, payload } => RawView::Tagged { tag, payload },
                api::CborNondetView::SimpleValue { _0: value } => RawView::Simple(value),
            }
        }

        fn to_vec(item: Self) -> Result<Vec<u8>, String> {
            to_vec(item)
        }

        fn mk_int64(negative: bool, magnitude: u64) -> Self {
            let kind = if negative {
                api::CborNondetIntKind::NegInt64
            } else {
                api::CborNondetIntKind::UInt64
            };
            api::cbor_nondet_mk_int64(kind, magnitude)
        }

        fn mk_simple(value: u8) -> Option<Self> {
            api::cbor_nondet_mk_simple_value(value)
        }

        fn mk_text(value: &'a str) -> Option<Self> {
            api::cbor_nondet_mk_text_string(value)
        }

        fn mk_bytes(value: &'a [u8]) -> Option<Self> {
            api::cbor_nondet_mk_byte_string(value)
        }

        fn mk_tagged(tag: u64, payload: &'a Self) -> Self {
            api::cbor_nondet_mk_tagged(tag, payload)
        }

        fn mk_array(items: &'a [Self]) -> Option<Self> {
            api::cbor_nondet_mk_array(items)
        }

        fn mk_map_entry(key: Self, value: Self) -> Self::MapEntry {
            api::cbor_nondet_mk_map_entry(key, value)
        }

        fn mk_map(entries: &'a mut [Self::MapEntry]) -> Option<Self> {
            api::cbor_nondet_mk_map(entries)
        }
    }
}

/// Selects an EverCBOR implementation without naming any of its lifetimes.
///
/// Implemented by [`Det`] and [`Nondet`] only.
pub trait Mode: Sized {
    /// The backend item type for a given borrow.
    #[doc(hidden)]
    type Item<'x>: Backend<'x>;

    /// Serializes with this mode's backend.
    ///
    /// Kept per mode rather than written generically: over a generic element
    /// type, drop checking cannot retire the arena borrows before the call
    /// returns.
    #[doc(hidden)]
    fn value_to_vec(value: &CborValue<'_>, max_depth: usize) -> Result<Vec<u8>, String>;
}

/// Deterministic CBOR, per RFC 8949 Section 4.2.1.
///
/// Parsing rejects non-canonical encodings. Serialization sorts map keys and
/// rejects duplicates.
pub struct Det;

/// Definite-length CBOR in any well-formed encoding.
///
/// Parsing accepts non-canonical encodings. Serialization preserves map entry
/// order as given.
pub struct Nondet;

impl Mode for Det {
    type Item<'x> = cborrs::cbordet::CborDet<'x>;

    fn value_to_vec(value: &CborValue<'_>, max_depth: usize) -> Result<Vec<u8>, String> {
        det_backend::value_to_vec(value, max_depth)
    }
}

impl Mode for Nondet {
    type Item<'x> = cborrs_nondet::cbornondet::CborNondet<'x>;

    fn value_to_vec(value: &CborValue<'_>, max_depth: usize) -> Result<Vec<u8>, String> {
        nondet_backend::value_to_vec(value, max_depth)
    }
}

/// A CBOR value supporting arbitrary nesting.
///
/// Covers the major CBOR types: integers, simple values, byte/text strings,
/// arrays, maps, and tagged values.
///
/// Byte and text payloads are held in [`Cow`], so a value parsed from a buffer
/// borrows from it and a value built from owned data carries it.
/// [`CborValue::into_owned`] detaches a parsed value from its input.
#[derive(Clone, PartialEq)]
pub enum CborValue<'a> {
    /// Positive or negative integer.
    Int(i64),
    /// CBOR simple value, such as `false`, `true`, or `null`.
    Simple(u8),
    /// CBOR byte string.
    ByteString(Cow<'a, [u8]>),
    /// CBOR UTF-8 text string.
    TextString(Cow<'a, str>),
    /// CBOR array.
    Array(Vec<CborValue<'a>>),
    /// CBOR map stored as key/value pairs.
    Map(Vec<(CborValue<'a>, CborValue<'a>)>),
    /// CBOR tagged value.
    Tagged {
        tag: u64,
        payload: Box<CborValue<'a>>,
    },
}

impl<'a> CborValue<'a> {
    /// Build a byte string, borrowing or taking ownership as given.
    pub fn bytes(value: impl Into<Cow<'a, [u8]>>) -> Self {
        CborValue::ByteString(value.into())
    }

    /// Build a text string, borrowing or taking ownership as given.
    pub fn text(value: impl Into<Cow<'a, str>>) -> Self {
        CborValue::TextString(value.into())
    }

    /// Parse CBOR bytes in the given [`Mode`], up to
    /// [`MAX_CBOR_NESTING_DEPTH`].
    ///
    /// The entire input must be consumed; trailing bytes are rejected. Byte
    /// and text payloads in the result borrow from `bytes`.
    pub fn parse<M: Mode>(bytes: &'a [u8]) -> Result<Self, String> {
        Self::parse_with_depth::<M>(bytes, MAX_CBOR_NESTING_DEPTH)
    }

    /// Parse CBOR bytes in the given [`Mode`], rejecting inputs nested deeper
    /// than `max_depth`.
    pub fn parse_with_depth<M: Mode>(bytes: &'a [u8], max_depth: usize) -> Result<Self, String> {
        let (item, remainder) = <M::Item<'a>>::parse(bytes).ok_or("Failed to parse CBOR bytes")?;
        if !remainder.is_empty() {
            return Err(format!(
                "Trailing bytes: {} unconsumed byte(s)",
                remainder.len()
            ));
        }
        Self::from_raw::<M::Item<'a>>(item, max_depth)
    }

    /// Parse leniently, accepting any well-formed definite-length encoding.
    pub fn parse_nondet(bytes: &'a [u8]) -> Result<Self, String> {
        Self::parse::<Nondet>(bytes)
    }

    /// Parse strictly, rejecting encodings that are not deterministic.
    pub fn parse_det(bytes: &'a [u8]) -> Result<Self, String> {
        Self::parse::<Det>(bytes)
    }

    /// Parse leniently into a value that borrows nothing from `bytes`.
    #[deprecated(note = "renamed to `parse_nondet`, which borrows from `bytes` instead of copying")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(CborValue::parse_nondet(bytes)?.into_owned())
    }

    /// Serialize in the given [`Mode`], rejecting values nested deeper than
    /// `max_depth`.
    pub fn to_bytes_with_depth<M: Mode>(&self, max_depth: usize) -> Result<Vec<u8>, String> {
        M::value_to_vec(self, max_depth)
    }

    /// Serialize to deterministic CBOR, sorting map keys.
    pub fn to_bytes_det(&self) -> Result<Vec<u8>, String> {
        self.to_bytes_with_depth::<Det>(MAX_CBOR_NESTING_DEPTH)
    }

    /// Serialize preserving map entry order as given.
    ///
    /// Detecting duplicate keys without sorting takes time quadratic in the
    /// number of map entries. [`CborValue::to_bytes_det`] sorts instead, and
    /// is the cheaper choice for large maps.
    pub fn to_bytes_nondet(&self) -> Result<Vec<u8>, String> {
        self.to_bytes_with_depth::<Nondet>(MAX_CBOR_NESTING_DEPTH)
    }

    /// Serialize to deterministic CBOR, sorting map keys.
    #[deprecated(note = "renamed to `to_bytes_det`")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        self.to_bytes_det()
    }

    /// Detach from any borrowed input, producing an independently owned value.
    ///
    /// Payloads that are already owned are moved rather than copied.
    pub fn into_owned(self) -> CborValue<'static> {
        match self {
            CborValue::Int(v) => CborValue::Int(v),
            CborValue::Simple(v) => CborValue::Simple(v),
            CborValue::ByteString(b) => CborValue::ByteString(Cow::Owned(b.into_owned())),
            CborValue::TextString(s) => CborValue::TextString(Cow::Owned(s.into_owned())),
            CborValue::Array(items) => {
                CborValue::Array(items.into_iter().map(CborValue::into_owned).collect())
            }
            CborValue::Map(entries) => CborValue::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect(),
            ),
            CborValue::Tagged { tag, payload } => CborValue::Tagged {
                tag,
                payload: Box::new(payload.into_owned()),
            },
        }
    }

    /// Get an array element by index.
    ///
    /// Returns an error if this value is not an array or if `index` is out of
    /// bounds.
    pub fn array_at(&self, index: usize) -> Result<&CborValue<'a>, String> {
        match self {
            CborValue::Array(items) => items
                .get(index)
                .ok_or_else(|| format!("Index {index} out of bounds")),
            other => Err(format!("Expected Array, got {:?}", other.type_name())),
        }
    }

    /// Look up a map value by integer key.
    ///
    /// Returns an error if this value is not a map or if the key is absent.
    pub fn map_at_int(&self, key: i64) -> Result<&CborValue<'a>, String> {
        self.map_at(&CborValue::Int(key))
    }

    /// Look up a map value by text string key.
    ///
    /// Returns an error if this value is not a map or if the key is absent.
    pub fn map_at_str(&self, key: &str) -> Result<&CborValue<'a>, String> {
        self.map_at(&CborValue::text(key))
    }

    /// Return whether a map has an integer key.
    ///
    /// Returns an error if this value is not a map.
    pub fn map_has_int_key(&self, key: i64) -> Result<bool, String> {
        self.map_has_key(&CborValue::Int(key))
    }

    /// Return whether a map has a text string key.
    ///
    /// Returns an error if this value is not a map.
    pub fn map_has_str_key(&self, key: &str) -> Result<bool, String> {
        self.map_has_key(&CborValue::text(key))
    }

    /// Return whether a map has a [`CborValue`] key.
    ///
    /// Returns an error if this value is not a map.
    pub fn map_has_key(&self, key: &CborValue<'_>) -> Result<bool, String> {
        match self {
            CborValue::Map(entries) => Ok(entries.iter().any(|(k, _)| k == key)),
            other => Err(format!("Expected Map, got {:?}", other.type_name())),
        }
    }

    /// Look up a map value by a [`CborValue`] key.
    ///
    /// Returns an error if this value is not a map or if the key is absent.
    pub fn map_at(&self, key: &CborValue<'_>) -> Result<&CborValue<'a>, String> {
        match self {
            CborValue::Map(entries) => entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .ok_or_else(|| format!("Key {key:?} not found in map")),
            other => Err(format!("Expected Map, got {:?}", other.type_name())),
        }
    }

    /// Iterate over array elements.
    ///
    /// Returns an error if this value is not an array.
    pub fn iter_array(&self) -> Result<std::slice::Iter<'_, CborValue<'a>>, String> {
        match self {
            CborValue::Array(items) => Ok(items.iter()),
            other => Err(format!("Expected Array, got {:?}", other.type_name())),
        }
    }

    /// Iterate over map entries as `(key, value)` pairs.
    ///
    /// Returns an error if this value is not a map.
    pub fn iter_map(
        &self,
    ) -> Result<impl Iterator<Item = (&CborValue<'a>, &CborValue<'a>)>, String> {
        match self {
            CborValue::Map(entries) => Ok(entries.iter().map(|(k, v)| (k, v))),
            other => Err(format!("Expected Map, got {:?}", other.type_name())),
        }
    }

    /// Number of elements in an array or map.
    ///
    /// Returns an error for other value types.
    pub fn len(&self) -> Result<usize, String> {
        match self {
            CborValue::Array(items) => Ok(items.len()),
            CborValue::Map(entries) => Ok(entries.len()),
            other => Err(format!("len() not applicable to {:?}", other.type_name())),
        }
    }

    /// Whether an array or map has no elements.
    ///
    /// Returns an error for other value types.
    pub fn is_empty(&self) -> Result<bool, String> {
        self.len().map(|len| len == 0)
    }

    fn type_name(&self) -> &'static str {
        match self {
            CborValue::Int(_) => "Int",
            CborValue::Simple(_) => "Simple",
            CborValue::ByteString(_) => "ByteString",
            CborValue::TextString(_) => "TextString",
            CborValue::Array(_) => "Array",
            CborValue::Map(_) => "Map",
            CborValue::Tagged { .. } => "Tagged",
        }
    }

    /// Budget for the children of a container holding `child_count` of them.
    ///
    /// An empty container has no children to descend into, so it does not
    /// spend any of the budget.
    fn child_budget(budget: usize, child_count: usize) -> Result<usize, String> {
        if child_count == 0 {
            return Ok(budget);
        }
        budget
            .checked_sub(1)
            .ok_or_else(|| "Maximum CBOR nesting depth exceeded".to_string())
    }

    fn from_raw<B: Backend<'a>>(item: B, budget: usize) -> Result<Self, String> {
        Ok(match B::destruct(item) {
            RawView::Int64 {
                negative,
                magnitude,
            } => CborValue::Int(int_from_magnitude(negative, magnitude)?),
            RawView::Simple(value) => CborValue::Simple(value),
            RawView::ByteString(payload) => CborValue::ByteString(Cow::Borrowed(payload)),
            RawView::TextString(payload) => CborValue::TextString(Cow::Borrowed(payload)),
            RawView::Array(children) => {
                let child_budget = Self::child_budget(budget, children.len())?;
                CborValue::Array(
                    children
                        .into_iter()
                        .map(|c| Self::from_raw::<B>(c, child_budget))
                        .collect::<Result<_, _>>()?,
                )
            }
            RawView::Map(children) => {
                let child_budget = Self::child_budget(budget, children.len())?;
                CborValue::Map(
                    children
                        .into_iter()
                        .map(|(k, v)| {
                            Ok((
                                Self::from_raw::<B>(k, child_budget)?,
                                Self::from_raw::<B>(v, child_budget)?,
                            ))
                        })
                        .collect::<Result<_, String>>()?,
                )
            }
            RawView::Tagged { tag, payload } => CborValue::Tagged {
                tag,
                payload: Box::new(Self::from_raw::<B>(
                    payload,
                    Self::child_budget(budget, 1)?,
                )?),
            },
        })
    }

    /// Build a backend tree without serializing.
    ///
    /// Child nodes are allocated in the arenas so they stay alive long enough
    /// for the parent to borrow them. The caller serializes the returned root
    /// exactly once.
    fn to_raw<'b, B: Backend<'b>>(
        &'b self,
        items: &'b SimpleArena<B>,
        entries: &'b SimpleArena<B::MapEntry>,
        budget: usize,
    ) -> Result<B, String> {
        match self {
            CborValue::Int(v) => {
                let (negative, magnitude) = magnitude_from_int(*v);
                Ok(B::mk_int64(negative, magnitude))
            }
            CborValue::Simple(v) => {
                B::mk_simple(*v).ok_or_else(|| "Failed to make CBOR simple value".to_string())
            }
            CborValue::ByteString(b) => {
                B::mk_bytes(b.as_ref()).ok_or_else(|| "Failed to make CBOR byte string".to_string())
            }
            CborValue::TextString(s) => {
                B::mk_text(s.as_ref()).ok_or_else(|| "Failed to make CBOR text string".to_string())
            }
            CborValue::Array(children) => {
                let child_budget = Self::child_budget(budget, children.len())?;
                let raw: Vec<B> = children
                    .iter()
                    .map(|c| c.to_raw(items, entries, child_budget))
                    .collect::<Result<_, _>>()?;
                B::mk_array(items.alloc_extend(raw))
                    .ok_or_else(|| "Failed to build CBOR array".to_string())
            }
            CborValue::Map(map_entries) => {
                let child_budget = Self::child_budget(budget, map_entries.len())?;
                let raw: Vec<B::MapEntry> = map_entries
                    .iter()
                    .map(|(k, v)| {
                        Ok(B::mk_map_entry(
                            k.to_raw(items, entries, child_budget)?,
                            v.to_raw(items, entries, child_budget)?,
                        ))
                    })
                    .collect::<Result<_, String>>()?;
                B::mk_map(entries.alloc_extend(raw))
                    .ok_or_else(|| "Failed to build CBOR map".to_string())
            }
            CborValue::Tagged { tag, payload } => {
                let inner = payload.to_raw(items, entries, Self::child_budget(budget, 1)?)?;
                Ok(B::mk_tagged(*tag, items.alloc(inner)))
            }
        }
    }
}

/// CBOR encodes a negative integer `n` as the magnitude `-1 - n`.
fn int_from_magnitude(negative: bool, magnitude: u64) -> Result<i64, String> {
    if !negative {
        return i64::try_from(magnitude)
            .map_err(|_| format!("CBOR uint {magnitude} exceeds i64 range"));
    }
    if magnitude > i64::MAX as u64 {
        return Err(format!("CBOR nint -1-{magnitude} exceeds i64 range"));
    }
    Ok(-1 - (magnitude as i64))
}

/// Inverse of [`int_from_magnitude`]. Negating through `u64` keeps
/// `i64::MIN` in range.
fn magnitude_from_int(value: i64) -> (bool, u64) {
    if value < 0 {
        (true, !(value as u64))
    } else {
        (false, value as u64)
    }
}

impl std::fmt::Debug for CborValue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CborValue::Int(v) => write!(f, "Int({v})"),
            CborValue::Simple(v) => write!(f, "Simple({v})"),
            CborValue::ByteString(b) => write!(f, "Bstr({} bytes)", b.len()),
            CborValue::TextString(s) => write!(f, "Tstr({s:?})"),
            CborValue::Array(items) => f.debug_list().entries(items).finish(),
            CborValue::Map(entries) => f
                .debug_map()
                .entries(entries.iter().map(|(k, v)| (k, v)))
                .finish(),
            CborValue::Tagged { tag, payload } => write!(f, "Tag({tag}, {payload:?})"),
        }
    }
}

#[cfg(test)]
mod tests;
