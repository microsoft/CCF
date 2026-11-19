/* FIXME: This module to be rewritten with `pub use crate::cbornondetver`,
 * once Karamel can extract Rust code with documentation (coming from
 * FStar attributes), abstract types, references instead of one-sized
 * slices, proper casing of type names, and native Rust
 * `std::Option`. */
//! This module is an implementation of Definite-Length CBOR
//! minus floating-point values, fully
//! formally verified for functional correctness and absence of panics
//! related to breach of abstraction, buffer overruns or arithmetic
//! overflow/underflow. This module never allocates into the heap, except
//! for the `*_alloc` functions, which allocate their scratch space.

/* FIXME: `cbornondet` to be defined as abstract in cbornondetveraux
 * already. I cannot abstract it here since `cbor_nondet_mk_tagged`,
 * `cbor_nondet_mk_array` and `cbor_nondet_mk_map` use references and arrays
 * of `cbornondet` elements as input arguments.
 */
/// An abstract type to represent a CBOR object, which
/// can be obtained either using "constructor" functions of this
/// module, or by parsing from serialized data. Declared in
/// `pulse/CBOR.Pulse.Nondet.API.Rust.fsti`. Its corresponding pure
/// ("mathematical") functional specification is the `cbor` type in
/// `spec/CBOR.Spec.Type.fsti`.
pub type CborNondet <'a> = crate::cbornondetver::cbornondet <'a>;

/// Tries to parse a Definite-Length CBOR object from the first bytes of
/// `input`, minus floating-point
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
/// Section 5.3.1, i.e. the absence of duplicate map keys, and the
/// well-formedness of UTF-8 text strings.
pub fn cbor_nondet_parse <'a>(map_key_bound: Option<usize>, strict_check: bool, input: &'a [u8]) ->
    Option<(CborNondet<'a>, &'a [u8])>
{
	let map_key_bound0 : crate::cbornondetveraux::option__size_t = match map_key_bound {
		None => {
			crate::cbornondetveraux::option__size_t::None
		}
		Some(v) => {
			crate::cbornondetveraux::option__size_t::Some {v: v}
		}
	};
    match crate::cbornondetver::cbor_nondet_parse(map_key_bound0, strict_check, input) {
	crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None => {
	    return None;
	}
	crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some {v} => {
	    let (object, rem) = v;
	    return Some((object, rem));
	}
    }
}

/// Like [`cbor_nondet_parse`], but rejects any map, at any nesting
/// depth, with more than `map_length_bound` entries.
pub fn cbor_nondet_parse_map_length_bounded<'a>(
    map_length_bound: usize,
    map_key_bound: Option<usize>,
    strict_check: bool,
    input: &'a [u8],
) -> Option<(CborNondet<'a>, &'a [u8])>
{
    let map_key_bound0 = match map_key_bound {
        None => crate::cbornondetveraux::option__size_t::None,
        Some(v) => crate::cbornondetveraux::option__size_t::Some { v },
    };
    match crate::cbornondetver::cbor_nondet_parse_map_length_bounded(
        map_length_bound,
        map_key_bound0,
        strict_check,
        input,
    ) {
        crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None => None,
        crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some { v } => Some(v),
    }
}

fn option_size_t_of_option(x: Option<usize>) -> crate::cbornondetveraux::option__size_t
{
    match x {
        None => crate::cbornondetveraux::option__size_t::None,
        Some(v) => crate::cbornondetveraux::option__size_t::Some { v },
    }
}

/// Parses a CBOR object with map nesting depth at most `map_depth_bound`
/// and at most `map_length_bound` entries in every map. If
/// `map_key_bound` is `Some(b)`, also rejects any object in which some
/// map key has map nesting depth more than `b`. Returns `None` on
/// failure, or the object and the remaining input on success.
pub fn cbor_nondet_parse_bounded<'a>(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: Option<usize>,
    input: &'a [u8],
) -> Option<(CborNondet<'a>, &'a [u8])>
{
    match crate::cbornondetver::cbor_nondet_parse_bounded(
        map_depth_bound,
        map_length_bound,
        option_size_t_of_option(map_key_bound),
        input,
    ) {
        crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None => None,
        crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some { v } => Some(v),
    }
}

/// Returns `true` if and only if a scratch slice of `scratch_len`
/// elements is large enough for [`cbor_nondet_parse_bounded_sort`]
/// with these bounds, i.e. `scratch_len >= 3 * map_depth_bound *
/// map_length_bound` (without overflow.)
pub fn cbor_nondet_bounded_sort_scratch_ok(
    map_depth_bound: usize,
    map_length_bound: usize,
    scratch_len: usize,
) -> bool
{
    crate::cbornondetver::cbor_nondet_bounded_sort_scratch_ok(map_depth_bound, map_length_bound, scratch_len)
}

/// Same specification as [`cbor_nondet_parse_bounded`], but checks
/// map keys for duplicates by sorting them, using the caller-provided
/// `scratch` slice instead of quadratic pairwise comparisons. `scratch`
/// must satisfy [`cbor_nondet_bounded_sort_scratch_ok`], otherwise this
/// function returns `None`. This function allocates nothing.
/// `scratch` is only borrowed for the duration of the call: the
/// returned object only borrows from `input`.
pub fn cbor_nondet_parse_bounded_sort<'a>(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: Option<usize>,
    scratch: &mut [usize],
    input: &'a [u8],
) -> Option<(CborNondet<'a>, &'a [u8])>
{
    // This is the verified crate::cbornondetver::cbor_nondet_parse_bounded_sort
    // (CBOR.Pulse.API.Base.cbor_nondet_parse_bounded_sort, instantiated in
    // CBOR.Pulse.API.Nondet.Rust), redone by hand calling the same verified
    // validator and parser. Karamel gives the same lifetime to all
    // reference arguments of a function returning a borrow, so the
    // extracted version requires `scratch` to outlive the result, although
    // the result only borrows from `input`.
    let len = crate::cbornondetveraux::cbor_nondet_validate_bounded_sort(
        map_depth_bound,
        map_length_bound,
        option_size_t_of_option(map_key_bound),
        scratch,
        input,
    );
    if len == 0 {
        None
    } else {
        let (inl, inr) = input.split_at(len);
        Some((crate::cbornondetveraux::cbor_nondet_parse_valid(inl, len), inr))
    }
}

/// Returns `true` if and only if scratch slices of `scratch_len` and
/// `hash_scratch_len` elements are large enough for
/// [`cbor_nondet_parse_bounded_hash`] with these bounds, i.e.
/// `scratch_len >= 3 * map_depth_bound * map_length_bound +
/// map_length_bound` and `hash_scratch_len >= map_length_bound`
/// (without overflow.)
pub fn cbor_nondet_bounded_hash_scratch_ok(
    map_depth_bound: usize,
    map_length_bound: usize,
    scratch_len: usize,
    hash_scratch_len: usize,
) -> bool
{
    crate::cbornondetver::cbor_nondet_bounded_hash_scratch_ok(map_depth_bound, map_length_bound, scratch_len, hash_scratch_len)
}

/// Same specification as [`cbor_nondet_parse_bounded`], but checks
/// map keys for duplicates by sorting them by their SipHash-1-3 hash
/// keyed with `(k0, k1)` first, comparing them with the CBOR canonical
/// order only when their hashes are equal. The result does not depend
/// on the key; but if the key is secret and random, adversarial inputs
/// cannot predictably cause hash collisions, so that the check is
/// fast even when map keys contain maps (see
/// [`cbor_nondet_parse_bounded_hash_random`].) `scratch` and
/// `hash_scratch` must satisfy [`cbor_nondet_bounded_hash_scratch_ok`],
/// otherwise this function returns `None`. This function allocates
/// nothing. `scratch` and `hash_scratch` are only borrowed for the
/// duration of the call: the returned object only borrows from `input`.
pub fn cbor_nondet_parse_bounded_hash<'a>(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: Option<usize>,
    k0: u64,
    k1: u64,
    scratch: &mut [usize],
    hash_scratch: &mut [u64],
    input: &'a [u8],
) -> Option<(CborNondet<'a>, &'a [u8])>
{
    // This is the verified crate::cbornondetver::cbor_nondet_parse_bounded_hash
    // (CBOR.Pulse.API.Base.cbor_nondet_parse_bounded_hash), redone by hand
    // for the same lifetime reason as in cbor_nondet_parse_bounded_sort.
    let len = crate::cbornondetveraux::cbor_nondet_validate_bounded_hash(
        map_depth_bound,
        map_length_bound,
        option_size_t_of_option(map_key_bound),
        k0,
        k1,
        scratch,
        hash_scratch,
        input,
    );
    if len == 0 {
        None
    } else {
        let (inl, inr) = input.split_at(len);
        Some((crate::cbornondetveraux::cbor_nondet_parse_valid(inl, len), inr))
    }
}

/// Returns a fresh random SipHash key, derived from the randomly
/// seeded [`std::collections::hash_map::RandomState`] (the standard
/// library seeds it from the operating system's random number
/// generator.)
pub fn cbor_nondet_random_hash_key() -> (u64, u64)
{
    use std::hash::{BuildHasher, Hasher};
    let st = std::collections::hash_map::RandomState::new();
    let mut h0 = st.build_hasher();
    h0.write_u8(0);
    let mut h1 = st.build_hasher();
    h1.write_u8(1);
    (h0.finish(), h1.finish())
}

/// Same as [`cbor_nondet_parse_bounded_hash`], with a fresh random key
/// from [`cbor_nondet_random_hash_key`]. This function allocates
/// nothing on the heap.
pub fn cbor_nondet_parse_bounded_hash_random<'a>(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: Option<usize>,
    scratch: &mut [usize],
    hash_scratch: &mut [u64],
    input: &'a [u8],
) -> Option<(CborNondet<'a>, &'a [u8])>
{
    let (k0, k1) = cbor_nondet_random_hash_key();
    cbor_nondet_parse_bounded_hash(map_depth_bound, map_length_bound, map_key_bound, k0, k1, scratch, hash_scratch, input)
}

/// Same specification as [`cbor_nondet_parse_bounded_sort`], but the
/// scratch space is allocated on the heap once (with
/// `Vec::try_reserve_exact`, through a small trusted allocator
/// interface), and freed before returning. Besides invalid input,
/// this function may also return `None` if the scratch space size
/// overflows or cannot be allocated. Allocation failure does not abort.
pub fn cbor_nondet_parse_bounded_sort_alloc<'a>(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: Option<usize>,
    input: &'a [u8],
) -> Option<(CborNondet<'a>, &'a [u8])>
{
    match crate::cbornondetver::cbor_nondet_parse_bounded_sort_alloc(map_depth_bound, map_length_bound, option_size_t_of_option(map_key_bound), input) {
        crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None => None,
        crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some { v } => Some(v),
    }
}

/// Same specification as [`cbor_nondet_parse_bounded_hash`], but both
/// scratch spaces are allocated on the heap once, and freed before
/// returning (see [`cbor_nondet_parse_bounded_sort_alloc`].)
pub fn cbor_nondet_parse_bounded_hash_alloc<'a>(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: Option<usize>,
    k0: u64,
    k1: u64,
    input: &'a [u8],
) -> Option<(CborNondet<'a>, &'a [u8])>
{
    match crate::cbornondetver::cbor_nondet_parse_bounded_hash_alloc(map_depth_bound, map_length_bound, option_size_t_of_option(map_key_bound), k0, k1, input) {
        crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None => None,
        crate::cbornondetveraux::option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some { v } => Some(v),
    }
}

/// Same as [`cbor_nondet_parse_bounded_hash_alloc`], with a fresh
/// random key from [`cbor_nondet_random_hash_key`].
pub fn cbor_nondet_parse_bounded_hash_alloc_random<'a>(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: Option<usize>,
    input: &'a [u8],
) -> Option<(CborNondet<'a>, &'a [u8])>
{
    let (k0, k1) = cbor_nondet_random_hash_key();
    cbor_nondet_parse_bounded_hash_alloc(map_depth_bound, map_length_bound, map_key_bound, k0, k1, input)
}

/// Computes the byte size of the binary representation of the
/// CBOR object `x`,
/// but without serializing `x`. Returns `None` if that size is
/// strictly larger than `bound`; `Some(size)` otherwise. This function
/// uses stack space in the order of the level of nesting of the use
/// of "constructor" functions used to build `x`; the computation of
/// the sizes of those "subobjects" of `x` obtained from
/// `cbor_nondet_parse` uses only constant extra stack space for each
/// such subobject (in the sense that the computation does not
/// recursively nest into such subobjects.)
pub fn cbor_nondet_size <'a>(x: CborNondet <'a>, bound: usize) -> Option<usize>
{
	let res = crate::cbornondetver::cbor_nondet_size(x, bound);
    if res == 0 {
	    return None;
	} else {
	    return Some(res);
	}
}

/// Writes the binary representation of the CBOR object
/// `x` into the first bytes of the `output` byte slice.
/// This function first checks the size of `x` and
/// returns `None` if it is larger than the size of `output`;
/// otherwise it returns `Some(size)`, where `size` is the byte size
/// of `x`, the number of bytes written to `output`. This function
/// uses stack space in the order of the level of nesting of the use
/// of "constructor" functions used to build `x`; the serialization of
/// those "subobjects" of `x` obtained from `cbor_nondet_parse` uses only
/// constant extra stack space for each such subobject (in the sense
/// that the serialization does not recursively nest into such
/// subobjects.)
pub fn cbor_nondet_serialize <'a>(x: CborNondet <'a>, output: &'a mut [u8]) ->
    Option<usize>
{
    match crate::cbornondetver::cbor_nondet_serialize(x, output) {
	crate::cbornondetveraux::option__size_t::None => {
	    return None;
	}
	crate::cbornondetveraux::option__size_t::Some {v} => {
	    return Some(v);
	}
    }
}

/// Constructs a CBOR object of "simple value" type,
/// with value `v`. Returns `None` if the value `v` lies in the
/// reserved range (`24..31`), as specified by Table 4 of RFC 8949
/// Section 3.3; `Some(object)` otherwise.
pub fn cbor_nondet_mk_simple_value <'a>(v: u8) -> Option<CborNondet<'a>>
{
    match crate::cbornondetver::cbor_nondet_mk_simple_value(v) {
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    return None;
	}
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    return Some(v);
	}
    }
}

/// The kind of 64-bit integer: unsigned (to represent non-negative
/// values), or negative (to represent negative values in two's
/// complement.)
#[derive(PartialEq, Clone, Copy)]
pub enum CborNondetIntKind
{
    UInt64,
    NegInt64
}

/// Constructs a CBOR object of "integer" type, with
/// kind `ty` and value `v`.
pub fn cbor_nondet_mk_int64 <'a>(ty: CborNondetIntKind, v: u64) ->
    CborNondet <'a>
{
    let ty· : crate::cbornondetver::cbor_nondet_int_kind =
	match ty {
	    CborNondetIntKind::UInt64 => {
		crate::cbornondetver::cbor_nondet_int_kind::UInt64
	    }
	    CborNondetIntKind::NegInt64 => {
		crate::cbornondetver::cbor_nondet_int_kind::NegInt64
	    }
	};
    crate::cbornondetver::cbor_nondet_mk_int64(ty·, v)
}

/// Constructs a CBOR object of "text string" type, with
/// the contents of `s` as value. This function does not perform any
/// copy of its input `s`. It returns `None` if the byte size of `s`
/// is larger than $2^64 - 1$, `Some(object)` otherwise. This function
/// respects the UTF-8 well-formedness invariants.
pub fn cbor_nondet_mk_text_string <'a>(s: &'a str) ->
    Option<CborNondet<'a>>
{
    let ty· : crate::cbornondetver::cbor_nondet_string_kind =
	crate::cbornondetver::cbor_nondet_string_kind::TextString;
    match crate::cbornondetver::cbor_nondet_mk_string(ty·, s.as_bytes()) {
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v } => {
	    Some(v)
	}
    }
}

/// Constructs a CBOR object of "byte string" type, with
/// the contents of `s` as value. This function does not perform any
/// copy of its input `s`. It returns `None` if the byte size of `s`
/// is larger than $2^64 - 1$, `Some(object)` otherwise.
pub fn cbor_nondet_mk_byte_string <'a>(s: &'a [u8]) ->
    Option<CborNondet<'a>>
{
    let ty· : crate::cbornondetver::cbor_nondet_string_kind =
	crate::cbornondetver::cbor_nondet_string_kind::ByteString;
    match crate::cbornondetver::cbor_nondet_mk_string(ty·, s) {
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v } => {
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
/// Constructs a CBOR object of Tagged type, with tag
/// `tag`, and the contents of `r` as value. This function does not
/// perform any copy of its input `r`.
pub fn cbor_nondet_mk_tagged <'a>(tag: u64, r: &'a CborNondet <'a>) ->
    CborNondet <'a>
{
    return crate::cbornondetver::cbor_nondet_mk_tagged(tag, std::slice::from_ref(r));
}

/// Constructs a CBOR of "array" type. This function
/// does not copy its input array. It returns `None` if the input
/// array has more than $2^64 - 1$ elements, `Some(object)` otherwise.
pub fn cbor_nondet_mk_array <'a>(a: &'a [CborNondet <'a>]) ->
    Option<CborNondet<'a>>
{
    match crate::cbornondetver::cbor_nondet_mk_array(a) {
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    Some(v)
	}
    }
}

/* FIXME: this type to be defined as abstract in cbornondetveraux
 * already. I cannot abstract it here since `cbor_nondet_mk_map` uses
 * arrays of map entry elements as input arguments.
 */
/// The type of key-value map entries.
pub type CborNondetMapEntry <'a> = crate::cbornondetveraux::cbor_map_entry <'a>;

/// Constructs a map entry from a key `xk` and a value `xv`.
pub fn cbor_nondet_mk_map_entry <'a>(
    xk: CborNondet <'a>,
    xv: CborNondet <'a>
) ->
    CborNondetMapEntry <'a>
{
    return crate::cbornondetver::cbor_nondet_mk_map_entry(xk, xv);
}

/// Constructs a map from a slice of map entries. This function does
/// not copy its input array. If the input slice has more than $2^64 -
/// 1$ entries, then this function returns `None` and does not change
/// the input slice. Otherwise, this function checks for duplicate
/// keys. If duplicate keys are detected, then this function returns
/// `None`. Otherwise, it returns `Some(object)`. Due to the duplicate,
/// key detection, this function consumes stack space linear in the maximum
/// nesting of map entry keys.
pub fn cbor_nondet_mk_map <'a>(a: &'a mut [CborNondetMapEntry <'a>]) ->
    Option<CborNondet<'a>>
{
    match crate::cbornondetver::cbor_nondet_mk_map(a) {
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    Some(v)
	}
    }
}

/// Compares CBOR objects for semantic equality. This
/// function consumes stack space linear in the maximum nesting of its
/// two arguments.
pub fn cbor_nondet_equal <'a>(
    x1: CborNondet <'a>,
    x2: CborNondet <'a>
) ->
    bool
{
    crate::cbornondetver::cbor_nondet_equal(x1, x2)
}

/// The read-only type of CBOR arrays. Values of this
/// type cannot be manually constructed by the user, they are meant to
/// be obtained only via `cbor_nondet_destruct` below. The abstraction is
/// justified by the use of a refinement type, as per the definition
/// of `cbor_nondet_array` in `pulse/CBOR.Pulse.Nondet.API.Rust.fst`
#[derive(PartialEq, Clone, Copy)]
pub struct CborNondetArray <'a> { array: crate::cbornondetver::cbor_nondet_array <'a> }

/// The read-only type of CBOR maps. Values of this
/// type cannot be manually constructed by the user, they are meant to
/// be obtained only via `cbor_nondet_destruct` below. The abstraction is
/// justified by the use of a refinement type, as per the definition
/// of `cbor_nondet_map` in `pulse/CBOR.Pulse.Nondet.API.Rust.fst`
#[derive(PartialEq, Clone, Copy)]
pub struct CborNondetMap <'a> { map: crate::cbornondetver::cbor_nondet_map <'a> }

/// A read-only view of a CBOR object, as obtained by
/// peeling the first layer of nesting via `cbor_nondet_destruct` below.
#[derive(PartialEq, Clone, Copy)]
pub enum CborNondetView <'a>
{
    Int64 { kind: CborNondetIntKind, value: u64 },
    ByteString { payload: &'a [u8] },
    TextString { payload: &'a str },
    Array { _0: CborNondetArray <'a> },
    Map { _0: CborNondetMap <'a> },
    Tagged { tag: u64, payload: CborNondet <'a> },
    SimpleValue { _0: u8 }
}

/// Destructs a CBOR object by peeling its first layer
/// of nesting. This function does not recursively descend into array
/// or map payloads, and only reads the header of a tagged payload. As
/// such, it consumes constant stack space. This function respects the
/// UTF-8 well-formedness invariants.
pub fn cbor_nondet_destruct <'a>(c: CborNondet <'a>) -> CborNondetView <'a>
{
    match crate::cbornondetver::cbor_nondet_destruct(c) {
	crate::cbornondetver::cbor_nondet_view::Int64 { kind, value } => {
	    let kind· : CborNondetIntKind =
		match kind {
		    crate::cbornondetver::cbor_nondet_int_kind::UInt64 => {
			CborNondetIntKind::UInt64
		    }
		    crate::cbornondetver::cbor_nondet_int_kind::NegInt64 => {
			CborNondetIntKind::NegInt64
		    }
		};
	    CborNondetView::Int64 {kind: kind·, value}
	}
	crate::cbornondetver::cbor_nondet_view::String { kind, payload } => {
	    match kind {
		crate::cbornondetver::cbor_nondet_string_kind::ByteString => {
		    CborNondetView::ByteString {payload}
		}
		crate::cbornondetver::cbor_nondet_string_kind::TextString => {
		    CborNondetView::TextString {payload: std::str::from_utf8(payload).unwrap()}
		}
	    }
	}
	crate::cbornondetver::cbor_nondet_view::Array { _0 } => {
	    CborNondetView::Array { _0: CborNondetArray {array: _0 } }
	}
	crate::cbornondetver::cbor_nondet_view::Map { _0 } => {
	    CborNondetView::Map { _0: CborNondetMap {map: _0 } }
	}
	crate::cbornondetver::cbor_nondet_view::Tagged { tag, payload } => {
	    CborNondetView::Tagged {tag, payload}
	}
	crate::cbornondetver::cbor_nondet_view::SimpleValue { _0 } => {
	    CborNondetView::SimpleValue {_0}
	}
    }
}

/// Returns the number of elements in a CBOR array.
pub fn cbor_nondet_get_array_length <'a>(x: CborNondetArray <'a>) -> u64
{
    crate::cbornondetver::cbor_nondet_get_array_length(x.array)
}

/// The type of iterators over CBOR arrays. It is made
/// abstract since it is meant to be used with an implementation of
/// the `Iterator` trait only.
pub struct CborNondetArrayIterator <'a> { iter: crate::cbornondetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a> }

impl <'a> Iterator for CborNondetArrayIterator <'a> {
    type Item = CborNondet <'a>;
    fn next(&mut self) -> Option<Self::Item> {
	if crate::cbornondetver::cbor_nondet_array_iterator_is_empty(self.iter) {
	    None
	} else {
	    Some (crate::cbornondetver::cbor_nondet_array_iterator_next(std::slice::from_mut(& mut self.iter)))
	}
    }
}

impl <'a> IntoIterator for CborNondetArray <'a> {
    type Item = CborNondet <'a>;
    type IntoIter = CborNondetArrayIterator <'a>;
    fn into_iter(self) -> Self::IntoIter {
	CborNondetArrayIterator { iter: crate::cbornondetver::cbor_nondet_array_iterator_start(self.array) }
    }
}

/// Returns the `i`th element of the CBOR array `x`. Returns `None` if
/// `i` is equal to or larger than the number of array elements,
/// `Some(object)` otherwise.
pub fn cbor_nondet_get_array_item <'a>(x: CborNondetArray <'a>, i: u64) ->
    Option<CborNondet<'a>>
{
    match crate::cbornondetver::cbor_nondet_get_array_item(x.array, i) {
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    Some(v)
	}
    }
}

/// Returns the number of elements in a CBOR map.
pub fn cbor_nondet_get_map_length <'a>(x: CborNondetMap <'a>) -> u64
{
    crate::cbornondetver::cbor_nondet_map_length(x.map)
}

/// The type of iterators over CBOR maps. It is made
/// abstract since it is meant to be used with an implementation of
/// the `Iterator` trait only.
pub struct CborNondetMapIterator <'a> { iter: crate::cbornondetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a> }

impl <'a> Iterator for CborNondetMapIterator <'a> {
    type Item = CborNondetMapEntry <'a>;
    fn next(&mut self) -> Option<Self::Item> {
	if crate::cbornondetver::cbor_nondet_map_iterator_is_empty(self.iter) {
	    None
	} else {
	    Some (crate::cbornondetver::cbor_nondet_map_iterator_next(std::slice::from_mut(& mut self.iter)))
	}
    }
}

impl <'a> IntoIterator for CborNondetMap <'a> {
    type Item = CborNondetMapEntry <'a>;
    type IntoIter = CborNondetMapIterator <'a>;
    fn into_iter(self) -> Self::IntoIter {
	CborNondetMapIterator { iter: crate::cbornondetver::cbor_nondet_map_iterator_start(self.map) }
    }
}

/// Read the key of a map entry.
pub fn cbor_nondet_map_entry_key <'a>(x2: CborNondetMapEntry <'a>) ->
    CborNondet
    <'a>
{ crate::cbornondetver::cbor_nondet_map_entry_key(x2) }

/// Read the value of a map entry.
pub fn cbor_nondet_map_entry_value <'a>(x2: CborNondetMapEntry <'a>) ->
    CborNondet
    <'a>
{ crate::cbornondetver::cbor_nondet_map_entry_value(x2) }

/// Looks up a map `x` for an entry associated to the key `k`. If such
/// an entry exists, returns `Some(object)` where `object` is the
/// value associated to that key. Otherwise, returns `None`.
pub fn cbor_nondet_map_get <'a>(
    x: CborNondetMap <'a>,
    k: CborNondet <'a>
) ->
    Option<CborNondet<'a>>
{
    match crate::cbornondetver::cbor_nondet_map_get(x.map, k) {
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::None => {
	    None
	}
	crate::cbornondetveraux::option__CBOR_Pulse_Raw_Type_cbor_raw::Some {v} => {
	    Some(v)
	}
    }
}
