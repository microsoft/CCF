/* FIXME: This module to be rewritten with `pub use crate::cbordetver`,
 * once Karamel can extract Rust code with documentation (coming from
 * FStar attributes), abstract types, references instead of one-sized
 * slices, proper casing of type names, and native Rust
 * `std::Option`. */
//! This module is an implementation of Deterministically Encoded CBOR
//! (RFC 8949 Section 4.2.1) minus floating-point values, fully
//! formally verified for functional correctness and absence of panics
//! related to breach of abstraction, buffer overruns or arithmetic
//! overflow/underflow. This module never allocates into the heap.

/* FIXME: `cbordet` to be defined as abstract in cbordetveraux
 * already. I cannot abstract it here since `cbor_det_mk_tagged`,
 * `cbor_det_mk_array` and `cbor_det_mk_map` use references and arrays
 * of `cbordet` elements as input arguments.
 */
/// An abstract type to represent a Deterministic CBOR object, which
/// can be obtained either using "constructor" functions of this
/// module, or by parsing from serialized data. Declared in
/// `pulse/CBOR.Pulse.Det.API.Rust.fsti`. Its corresponding pure
/// ("mathematical") functional specification is the `cbor` type in
/// `spec/CBOR.Spec.Type.fsti`.
pub type CborDet <'a> = crate::cbordetver::cbordet <'a>;

/// Tries to parse a Deterministic CBOR object from the first bytes of
/// `input`, following RFC 8949 Section 4.2.1, minus floating-point
/// values. Returns `None` in case of failure, or `Some(object, rem)`
/// in case of success, where `rem` is the remainder of the input
/// slice past those first bytes of `input` that contain the valid
/// binary representation of
/// `input`. This function does not perform a deep parse of `input`,
/// it only copies the object type, tag and/or size of the top-most
/// object. As such, it uses constant stack space (including data
/// validation.) "Destructor" functions are to be used on the returned
/// object, to examine each level of nesting one at a time. NOTE: This
/// implementation checks for the basic validity constraints of
/// Section 5.3.1, i.e. the absence of duplicate map keys (which is a
/// consequence of the deterministic encoding.), and the
/// well-formedness of UTF-8 text strings.
pub fn cbor_det_parse <'a>(input: &'a [u8]) ->
    Option<(CborDet<'a>, &'a [u8])>
{
    match crate::cbordetver::cbor_det_parse(input) {
	crate::cbordetver::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None => {
	    return None;
	}
	crate::cbordetver::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some {v} => {
	    let (object, rem) = v;
	    return Some((object, rem));
	}
    }
}

/// Computes the byte size of the binary representation of the
/// Deterministic CBOR object `x` following RFC 8949 Section 4.2.1,
/// but without serializing `x`. Returns `None` if that size is
/// strictly larger than `bound`; `Some(size)` otherwise. This function
/// uses stack space in the order of the level of nesting of the use
/// of "constructor" functions used to build `x`; the computation of
/// the sizes of those "subobjects" of `x` obtained from
/// `cbor_det_parse` uses only constant extra stack space for each
/// such subobject (in the sense that the computation does not
/// recursively nest into such subobjects.)
pub fn cbor_det_size <'a>(x: CborDet <'a>, bound: usize) -> Option<usize>
{
    match crate::cbordetver::cbor_det_size(x, bound) {
	crate::cbordetver::option__size_t::None => {
	    return None;
	}
	crate::cbordetver::option__size_t::Some {v} => {
	    return Some(v);
	}
    }
}

/// Writes the binary representation of the Deterministic CBOR object
/// `x` into the first bytes of the `output` byte slice, following RFC
/// 8949 Section 4.2.1. This function first checks the size of `x` and
/// returns `None` if it is larger than the size of `output`;
/// otherwise it returns `Some(size)`, where `size` is the byte size
/// of `x`, the number of bytes written to `output`. This function
/// uses stack space in the order of the level of nesting of the use
/// of "constructor" functions used to build `x`; the serialization of
/// those "subobjects" of `x` obtained from `cbor_det_parse` uses only
/// constant extra stack space for each such subobject (in the sense
/// that the serialization does not recursively nest into such
/// subobjects.)
pub fn cbor_det_serialize <'a>(x: CborDet <'a>, output: &'a mut [u8]) ->
    Option<usize>
{
    match crate::cbordetver::cbor_det_serialize(x, output) {
	crate::cbordetver::option__size_t::None => {
	    return None;
	}
	crate::cbordetver::option__size_t::Some {v} => {
	    return Some(v);
	}
    }
}

/// Constructs a Deterministic CBOR object of "simple value" type,
/// with value `v`. Returns `None` if the value `v` lies in the
/// reserved range (`24..31`), as specified by Table 4 of RFC 8949
/// Section 3.3; `Some(object)` otherwise.
pub fn cbor_det_mk_simple_value <'a>(v: u8) -> Option<CborDet<'a>>
{
    match crate::cbordetver::cbor_det_mk_simple_value(v) {
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    return None;
	}
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    return Some(v);
	}
    }
}

/// The kind of 64-bit integer: unsigned (to represent non-negative
/// values), or negative (to represent negative values in two's
/// complement.)
#[derive(PartialEq, Clone, Copy)]
pub enum CborDetIntKind
{
    UInt64,
    NegInt64
}

/// Constructs a Deterministic CBOR object of "integer" type, with
/// kind `ty` and value `v`.
pub fn cbor_det_mk_int64 <'a>(ty: CborDetIntKind, v: u64) ->
    CborDet <'a>
{
    let ty· : crate::cbordetver::cbor_det_int_kind =
	match ty {
	    CborDetIntKind::UInt64 => {
		crate::cbordetver::cbor_det_int_kind::UInt64
	    }
	    CborDetIntKind::NegInt64 => {
		crate::cbordetver::cbor_det_int_kind::NegInt64
	    }
	};
    crate::cbordetver::cbor_det_mk_int64(ty·, v)
}

/// Constructs a Deterministic CBOR object of "text string" type, with
/// the contents of `s` as value. This function does not perform any
/// copy of its input `s`. It returns `None` if the byte size of `s`
/// is larger than $2^64 - 1$, `Some(object)` otherwise. This function
/// respects the UTF-8 well-formedness invariants.
pub fn cbor_det_mk_text_string <'a>(s: &'a str) ->
    Option<CborDet<'a>>
{
    let ty· : crate::cbordetver::cbor_det_string_kind =
	crate::cbordetver::cbor_det_string_kind::TextString;
    match crate::cbordetver::cbor_det_mk_string(ty·, s.as_bytes()) {
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v } => {
	    Some(v)
	}
    }
}

/// Constructs a Deterministic CBOR object of "byte string" type, with
/// the contents of `s` as value. This function does not perform any
/// copy of its input `s`. It returns `None` if the byte size of `s`
/// is larger than $2^64 - 1$, `Some(object)` otherwise.
pub fn cbor_det_mk_byte_string <'a>(s: &'a [u8]) ->
    Option<CborDet<'a>>
{
    let ty· : crate::cbordetver::cbor_det_string_kind =
	crate::cbordetver::cbor_det_string_kind::ByteString;
    match crate::cbordetver::cbor_det_mk_string(ty·, s) {
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v } => {
	    Some(v)
	}
    }
}

/* FIXME: this function to be extracted with references instead of
 * slices. The verified FStar/Pulse code is already using references,
 * but Karamel extracts them as slices. Because of that, I need to
 * manually write this piece of glue code to convert a reference into
 * a slice, which Karamel cannot extract (and FStar/Pulse cannot
 * currently model.)
 */
/// Constructs a Deterministic CBOR object of Tagged type, with tag
/// `tag`, and the contents of `r` as value. This function does not
/// perform any copy of its input `r`.
pub fn cbor_det_mk_tagged <'a>(tag: u64, r: &'a CborDet <'a>) ->
    CborDet <'a>
{
    return crate::cbordetver::cbor_det_mk_tagged(tag, std::slice::from_ref(r));
}

/// Constructs a Deterministic CBOR of "array" type. This function
/// does not copy its input array. It returns `None` if the input
/// array has more than $2^64 - 1$ elements, `Some(object)` otherwise.
pub fn cbor_det_mk_array <'a>(a: &'a [CborDet <'a>]) ->
    Option<CborDet<'a>>
{
    match crate::cbordetver::cbor_det_mk_array(a) {
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    Some(v)
	}
    }
}

/* FIXME: this type to be defined as abstract in cbordetveraux
 * already. I cannot abstract it here since `cbor_det_mk_map` uses
 * arrays of map entry elements as input arguments.
 */
/// The type of key-value map entries.
pub type CborDetMapEntry <'a> = crate::cbordetveraux::cbor_map_entry <'a>;

/// Constructs a map entry from a key `xk` and a value `xv`.
pub fn cbor_det_mk_map_entry <'a>(
    xk: CborDet <'a>,
    xv: CborDet <'a>
) ->
    CborDetMapEntry <'a>
{
    return crate::cbordetver::cbor_det_mk_map_entry(xk, xv);
}

/// Constructs a map from a slice of map entries. This function does
/// not copy its input array. If the input slice has more than $2^64 -
/// 1$ entries, then this function returns `None` and does not change
/// the input slice. Otherwise, this function tries to sort the input
/// slice in-place with respect to the key order specified in Section
/// 4.2.1 of RFC 8949 (without actually serializing the map entries.)
/// If the sorting detects duplicate keys, then this function returns
/// `None`. Otherwise, it returns `Some(object)`. Due to the sorting,
/// this function consumes stack space logarithmic in the size of the
/// input slice, and linear in the maximum nesting of map entry keys,
/// and the function may have changed the order of map entries in the
/// input slice.
pub fn cbor_det_mk_map <'a>(a: &'a mut [CborDetMapEntry <'a>]) ->
    Option<CborDet<'a>>
{
    match crate::cbordetver::cbor_det_mk_map(a) {
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    Some(v)
	}
    }
}

/// Compares Deterministic CBOR objects for semantic equality. This
/// function consumes stack space linear in the maximum nesting of its
/// two arguments.
pub fn cbor_det_equal <'a>(
    x1: CborDet <'a>,
    x2: CborDet <'a>
) ->
    bool
{
    crate::cbordetver::cbor_det_equal(x1, x2)
}

/// The read-only type of Deterministic CBOR arrays. Values of this
/// type cannot be manually constructed by the user, they are meant to
/// be obtained only via `cbor_det_destruct` below. The abstraction is
/// justified by the use of a refinement type, as per the definition
/// of `cbor_det_array` in `pulse/CBOR.Pulse.Det.API.Rust.fst`
#[derive(PartialEq, Clone, Copy)]
pub struct CborDetArray <'a> { array: crate::cbordetver::cbor_det_array <'a> }

/// The read-only type of Deterministic CBOR maps. Values of this
/// type cannot be manually constructed by the user, they are meant to
/// be obtained only via `cbor_det_destruct` below. The abstraction is
/// justified by the use of a refinement type, as per the definition
/// of `cbor_det_map` in `pulse/CBOR.Pulse.Det.API.Rust.fst`
#[derive(PartialEq, Clone, Copy)]
pub struct CborDetMap <'a> { map: crate::cbordetver::cbor_det_map <'a> }

/// A read-only view of a Deterministic CBOR object, as obtained by
/// peeling the first layer of nesting via `cbor_det_destruct` below.
#[derive(PartialEq, Clone, Copy)]
pub enum CborDetView <'a>
{
    Int64 { kind: CborDetIntKind, value: u64 },
    ByteString { payload: &'a [u8] },
    TextString { payload: &'a str },
    Array { _0: CborDetArray <'a> },
    Map { _0: CborDetMap <'a> },
    Tagged { tag: u64, payload: CborDet <'a> },
    SimpleValue { _0: u8 }
}

/// Destructs a Deterministic CBOR object by peeling its first layer
/// of nesting. This function does not recursively descend into array
/// or map payloads, and only reads the header of a tagged payload. As
/// such, it consumes constant stack space. This function respects the
/// UTF-8 well-formedness invariants.
pub fn cbor_det_destruct <'a>(c: CborDet <'a>) -> CborDetView <'a>
{
    match crate::cbordetver::cbor_det_destruct(c) {
	crate::cbordetver::cbor_det_view::Int64 { kind, value } => {
	    let kind· : CborDetIntKind =
		match kind {
		    crate::cbordetver::cbor_det_int_kind::UInt64 => {
			CborDetIntKind::UInt64
		    }
		    crate::cbordetver::cbor_det_int_kind::NegInt64 => {
			CborDetIntKind::NegInt64
		    }
		};
	    CborDetView::Int64 {kind: kind·, value}
	}
	crate::cbordetver::cbor_det_view::String { kind, payload } => {
	    match kind {
		crate::cbordetver::cbor_det_string_kind::ByteString => {
		    CborDetView::ByteString {payload}
		}
		crate::cbordetver::cbor_det_string_kind::TextString => {
		    CborDetView::TextString {payload: std::str::from_utf8(payload).unwrap()}
		}
	    }
	}
	crate::cbordetver::cbor_det_view::Array { _0 } => {
	    CborDetView::Array { _0: CborDetArray {array: _0 } }
	}
	crate::cbordetver::cbor_det_view::Map { _0 } => {
	    CborDetView::Map { _0: CborDetMap {map: _0 } }
	}
	crate::cbordetver::cbor_det_view::Tagged { tag, payload } => {
	    CborDetView::Tagged {tag, payload}
	}
	crate::cbordetver::cbor_det_view::SimpleValue { _0 } => {
	    CborDetView::SimpleValue {_0}
	}
    }
}

/// Returns the number of elements in a Deterministic CBOR array.
pub fn cbor_det_get_array_length <'a>(x: CborDetArray <'a>) -> u64
{
    crate::cbordetver::cbor_det_get_array_length(x.array)
}

/// The type of iterators over Deterministic CBOR arrays. It is made
/// abstract since it is meant to be used with an implementation of
/// the `Iterator` trait only.
pub struct CborDetArrayIterator <'a> { iter: crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a> }

impl <'a> Iterator for CborDetArrayIterator <'a> {
    type Item = CborDet <'a>;
    fn next(&mut self) -> Option<Self::Item> {
	if crate::cbordetver::cbor_det_array_iterator_is_empty(self.iter) {
	    None
	} else {
	    Some (crate::cbordetver::cbor_det_array_iterator_next(std::slice::from_mut(& mut self.iter)))
	}
    }
}

impl <'a> IntoIterator for CborDetArray <'a> {
    type Item = CborDet <'a>;
    type IntoIter = CborDetArrayIterator <'a>;
    fn into_iter(self) -> Self::IntoIter {
	CborDetArrayIterator { iter: crate::cbordetver::cbor_det_array_iterator_start(self.array) }
    }
}

/// Returns the `i`th element of the CBOR array `x`. Returns `None` if
/// `i` is equal to or larger than the number of array elements,
/// `Some(object)` otherwise.
pub fn cbor_det_get_array_item <'a>(x: CborDetArray <'a>, i: u64) ->
    Option<CborDet<'a>>
{
    match crate::cbordetver::cbor_det_get_array_item(x.array, i) {
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    Some(v)
	}
    }
}

/// Returns the number of elements in a Deterministic CBOR map.
pub fn cbor_det_get_map_length <'a>(x: CborDetMap <'a>) -> u64
{
    crate::cbordetver::cbor_det_map_length(x.map)
}

/// The type of iterators over Deterministic CBOR maps. It is made
/// abstract since it is meant to be used with an implementation of
/// the `Iterator` trait only.
pub struct CborDetMapIterator <'a> { iter: crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a> }

impl <'a> Iterator for CborDetMapIterator <'a> {
    type Item = CborDetMapEntry <'a>;
    fn next(&mut self) -> Option<Self::Item> {
	if crate::cbordetver::cbor_det_map_iterator_is_empty(self.iter) {
	    None
	} else {
	    Some (crate::cbordetver::cbor_det_map_iterator_next(std::slice::from_mut(& mut self.iter)))
	}
    }
}

impl <'a> IntoIterator for CborDetMap <'a> {
    type Item = CborDetMapEntry <'a>;
    type IntoIter = CborDetMapIterator <'a>;
    fn into_iter(self) -> Self::IntoIter {
	CborDetMapIterator { iter: crate::cbordetver::cbor_det_map_iterator_start(self.map) }
    }
}

/// Read the key of a map entry.
pub fn cbor_det_map_entry_key <'a>(x2: CborDetMapEntry <'a>) ->
    CborDet
    <'a>
{ crate::cbordetver::cbor_det_map_entry_key(x2) }

/// Read the value of a map entry.
pub fn cbor_det_map_entry_value <'a>(x2: CborDetMapEntry <'a>) ->
    CborDet
    <'a>
{ crate::cbordetver::cbor_det_map_entry_value(x2) }

/// Looks up a map `x` for an entry associated to the key `k`. If such
/// an entry exists, returns `Some(object)` where `object` is the
/// value associated to that key. Otherwise, returns `None`.
pub fn cbor_det_map_get <'a>(
    x: CborDetMap <'a>,
    k: CborDet <'a>
) ->
    Option<CborDet<'a>>
{
    match crate::cbordetver::cbor_det_map_get(x.map, k) {
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbordetver::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    Some(v)
	}
    }
}
