#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]
#![allow(unreachable_patterns)]

pub type cbordet <'a> = crate::cbordetveraux::cbor_raw <'a>;

pub fn cbor_det_reset_perm <'a>(x1: crate::cbordetveraux::cbor_raw <'a>) ->
    crate::cbordetveraux::cbor_raw
    <'a>
{ crate::cbordetveraux::cbor_raw_reset_perm_tot(x1) }

#[derive(PartialEq, Clone, Copy)]
pub enum option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t· <'a>
{
    None,
    Some { v: (crate::cbordetveraux::cbor_raw <'a>, &'a [u8]) }
}

pub fn cbor_det_parse <'a>(input: &'a [u8]) ->
    option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·
    <'a>
{
    let len: usize = crate::cbordetveraux::cbor_validate_det(input);
    if len == 0usize
    { option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None }
    else
    {
        let _letpattern: (&[u8], &[u8]) = input.split_at(len);
        let input2: &[u8] = _letpattern.0;
        let rem: &[u8] = _letpattern.1;
        let len1: usize = input2.len();
        let res: crate::cbordetveraux::cbor_raw = crate::cbordetveraux::cbor_parse(input2, len1);
        option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some
        { v: (res,rem) }
    }
}

#[derive(PartialEq, Clone, Copy)]
pub enum option__size_t
{
    None,
    Some { v: usize }
}

pub fn cbor_det_size(x: crate::cbordetveraux::cbor_raw, bound: usize) -> option__size_t
{
    let size: usize = crate::cbordetveraux::cbor_size(x, bound);
    if size == 0usize { option__size_t::None } else { option__size_t::Some { v: size } }
}

pub fn cbor_det_serialize(x: crate::cbordetveraux::cbor_raw, output: &mut [u8]) ->
    option__size_t
{
    let len: usize = crate::cbordetveraux::cbor_size(x, output.len());
    if len > 0usize
    {
        let _letpattern: (&mut [u8], &mut [u8]) = output.split_at_mut(len);
        let out: &mut [u8] = _letpattern.0;
        let _rem: &[u8] = _letpattern.1;
        let len·: usize = crate::cbordetveraux::cbor_serialize(x, out);
        option__size_t::Some { v: len· }
    }
    else
    { option__size_t::None }
}

#[derive(PartialEq, Clone, Copy)]
pub enum option__CBOR_Pulse_Raw_Type_cbor_raw <'a>
{
    None,
    Some { v: crate::cbordetveraux::cbor_raw <'a> }
}

pub fn cbor_det_mk_simple_value <'a>(v: u8) -> option__CBOR_Pulse_Raw_Type_cbor_raw <'a>
{
    if
    v <= crate::cbordetveraux::max_simple_value_additional_info
    ||
    crate::cbordetveraux::min_simple_value_long_argument <= v
    {
        let res: crate::cbordetveraux::cbor_raw =
            crate::cbordetveraux::cbor_raw::CBOR_Case_Simple { v };
        option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: res }
    }
    else
    { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
}

#[derive(PartialEq, Clone, Copy)]
pub enum cbor_det_int_kind
{
    UInt64,
    NegInt64
}

pub fn cbor_det_mk_int64 <'a>(ty: cbor_det_int_kind, v: u64) ->
    crate::cbordetveraux::cbor_raw
    <'a>
{
    let resi: crate::cbordetveraux::cbor_int =
        crate::cbordetveraux::cbor_int
        {
            cbor_int_type:
            if ty == cbor_det_int_kind::UInt64
            { crate::cbordetveraux::cbor_major_type_uint64 }
            else
            { crate::cbordetveraux::cbor_major_type_neg_int64 },
            cbor_int_size: (crate::cbordetveraux::mk_raw_uint64(v)).size,
            cbor_int_value: (crate::cbordetveraux::mk_raw_uint64(v)).value
        };
    crate::cbordetveraux::cbor_raw::CBOR_Case_Int { v: resi }
}

pub fn cbor_impl_utf8_correct(s: &[u8]) -> bool { crate::cbordetveraux::impl_correct(s) }

#[derive(PartialEq, Clone, Copy)]
pub enum cbor_det_string_kind
{
    ByteString,
    TextString
}

pub fn cbor_det_mk_string <'a>(ty: cbor_det_string_kind, s: &'a [u8]) ->
    option__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    let q1: usize = s.len().wrapping_div(32768usize);
    let q2: usize = q1.wrapping_div(32768usize);
    let q3: usize = q2.wrapping_div(32768usize);
    let q4: usize = q3.wrapping_div(32768usize);
    let __anf0: bool = q4 < 16usize;
    if ! __anf0
    { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
    else
    {
        let correct: bool =
            if ty == cbor_det_string_kind::TextString { cbor_impl_utf8_correct(s) } else { true };
        if correct
        {
            let len64: crate::cbordetveraux::raw_uint64 =
                crate::cbordetveraux::mk_raw_uint64(s.len() as u64);
            let ress: crate::cbordetveraux::cbor_string =
                crate::cbordetveraux::cbor_string
                {
                    cbor_string_type:
                    if ty == cbor_det_string_kind::ByteString
                    { crate::cbordetveraux::cbor_major_type_byte_string }
                    else
                    { crate::cbordetveraux::cbor_major_type_text_string },
                    cbor_string_size: len64.size,
                    cbor_string_ptr: s
                };
            let res: crate::cbordetveraux::cbor_raw =
                crate::cbordetveraux::cbor_raw::CBOR_Case_String { v: ress };
            option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: res }
        }
        else
        { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
    }
}

pub fn cbor_det_mk_tagged <'a>(tag: u64, r: &'a [crate::cbordetveraux::cbor_raw <'a>]) ->
    crate::cbordetveraux::cbor_raw
    <'a>
{
    let tag64: crate::cbordetveraux::raw_uint64 = crate::cbordetveraux::mk_raw_uint64(tag);
    let res·: crate::cbordetveraux::cbor_tagged =
        crate::cbordetveraux::cbor_tagged { cbor_tagged_tag: tag64, cbor_tagged_ptr: r };
    crate::cbordetveraux::cbor_raw::CBOR_Case_Tagged { v: res· }
}

pub type cbor_det_map_entry <'a> = crate::cbordetveraux::cbor_map_entry <'a>;

pub fn cbor_det_mk_map_entry <'a>(
    xk: crate::cbordetveraux::cbor_raw <'a>,
    xv: crate::cbordetveraux::cbor_raw <'a>
) ->
    crate::cbordetveraux::cbor_map_entry
    <'a>
{ crate::cbordetveraux::cbor_mk_map_entry(xk, xv) }

pub fn cbor_det_mk_array <'a>(a: &'a [crate::cbordetveraux::cbor_raw <'a>]) ->
    option__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    let q1: usize = a.len().wrapping_div(32768usize);
    let q2: usize = q1.wrapping_div(32768usize);
    let q3: usize = q2.wrapping_div(32768usize);
    let q4: usize = q3.wrapping_div(32768usize);
    let __anf0: bool = q4 < 16usize;
    if ! __anf0
    { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
    else
    {
        let len64: crate::cbordetveraux::raw_uint64 =
            crate::cbordetveraux::mk_raw_uint64(a.len() as u64);
        let res·: crate::cbordetveraux::cbor_array =
            crate::cbordetveraux::cbor_array
            { cbor_array_length_size: len64.size, cbor_array_ptr: a };
        let res: crate::cbordetveraux::cbor_raw =
            crate::cbordetveraux::cbor_raw::CBOR_Case_Array { v: res· };
        option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: res }
    }
}

pub fn cbor_det_mk_map <'a>(a: &'a mut [crate::cbordetveraux::cbor_map_entry <'a>]) ->
    option__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    let mut dest: [crate::cbordetveraux::cbor_raw; 1] =
        [crate::cbordetveraux::dummy_cbor_det_t(); 1usize];
    let q1: usize = a.len().wrapping_div(32768usize);
    let q2: usize = q1.wrapping_div(32768usize);
    let q3: usize = q2.wrapping_div(32768usize);
    let q4: usize = q3.wrapping_div(32768usize);
    let __anf0: bool = q4 < 16usize;
    let bres: bool =
        if ! __anf0
        { false }
        else
        {
            let correct: bool = crate::cbordetveraux::cbor_raw_sort(a);
            if correct
            {
                let raw_len: crate::cbordetveraux::raw_uint64 =
                    crate::cbordetveraux::mk_raw_uint64(a.len() as u64);
                let res·: crate::cbordetveraux::cbor_map =
                    crate::cbordetveraux::cbor_map
                    { cbor_map_length_size: raw_len.size, cbor_map_ptr: a };
                let res: crate::cbordetveraux::cbor_raw =
                    crate::cbordetveraux::cbor_raw::CBOR_Case_Map { v: res· };
                (&mut dest)[0usize] = res;
                true
            }
            else
            { false }
        };
    if bres
    {
        let res: crate::cbordetveraux::cbor_raw = (&dest)[0usize];
        option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: res }
    }
    else
    { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
}

pub fn cbor_det_equal(x1: crate::cbordetveraux::cbor_raw, x2: crate::cbordetveraux::cbor_raw) ->
    bool
{
    let comp: i16 = crate::cbordetveraux::impl_cbor_compare(x1, x2);
    comp == 0i16
}

pub fn cbor_det_major_type(x: crate::cbordetveraux::cbor_raw) -> u8
{ crate::cbordetveraux::impl_major_type(x) }

pub type cbor_det_array <'a> = crate::cbordetveraux::cbor_raw <'a>;

pub type cbor_det_map <'a> = crate::cbordetveraux::cbor_raw <'a>;

#[derive(PartialEq, Clone, Copy)]
enum cbor_det_view_tags
{
    Int64,
    String,
    Array,
    Map,
    Tagged,
    SimpleValue
}

#[derive(PartialEq, Clone, Copy)]
pub enum cbor_det_view <'a>
{
    Int64 { kind: cbor_det_int_kind, value: u64 },
    String { kind: cbor_det_string_kind, payload: &'a [u8] },
    Array { _0: crate::cbordetveraux::cbor_raw <'a> },
    Map { _0: crate::cbordetveraux::cbor_raw <'a> },
    Tagged { tag: u64, payload: crate::cbordetveraux::cbor_raw <'a> },
    SimpleValue { _0: u8 }
}

pub fn cbor_det_destruct <'a>(c: crate::cbordetveraux::cbor_raw <'a>) -> cbor_det_view <'a>
{
    let ty: u8 = cbor_det_major_type(c);
    if
    ty == crate::cbordetveraux::cbor_major_type_uint64
    ||
    ty == crate::cbordetveraux::cbor_major_type_neg_int64
    {
        let k: cbor_det_int_kind =
            if ty == crate::cbordetveraux::cbor_major_type_uint64
            { cbor_det_int_kind::UInt64 }
            else
            { cbor_det_int_kind::NegInt64 };
        let res: crate::cbordetveraux::raw_uint64 =
            match c
            {
                crate::cbordetveraux::cbor_raw::CBOR_Case_Int { v: c· } =>
                  crate::cbordetveraux::raw_uint64
                  { size: c·.cbor_int_size, value: c·.cbor_int_value },
                _ => panic!("Incomplete pattern matching")
            };
        let i: u64 = res.value;
        cbor_det_view::Int64 { kind: k, value: i }
    }
    else if
    ty == crate::cbordetveraux::cbor_major_type_byte_string
    ||
    ty == crate::cbordetveraux::cbor_major_type_text_string
    {
        let k: cbor_det_string_kind =
            if ty == crate::cbordetveraux::cbor_major_type_byte_string
            { cbor_det_string_kind::ByteString }
            else
            { cbor_det_string_kind::TextString };
        let s: &[u8] =
            match c
            {
                crate::cbordetveraux::cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_ptr,
                _ => panic!("Incomplete pattern matching")
            };
        cbor_det_view::String { kind: k, payload: s }
    }
    else if ty == crate::cbordetveraux::cbor_major_type_array
    { cbor_det_view::Array { _0: c } }
    else if ty == crate::cbordetveraux::cbor_major_type_map
    { cbor_det_view::Map { _0: c } }
    else if ty == crate::cbordetveraux::cbor_major_type_tagged
    {
        let res: crate::cbordetveraux::raw_uint64 =
            match c
            {
                crate::cbordetveraux::cbor_raw::CBOR_Case_Tagged { v: c· } => c·.cbor_tagged_tag,
                crate::cbordetveraux::cbor_raw::CBOR_Case_Serialized_Tagged { v: c· } =>
                  c·.cbor_serialized_header,
                _ => panic!("Incomplete pattern matching")
            };
        let tag: u64 = res.value;
        let payload: crate::cbordetveraux::cbor_raw =
            crate::cbordetveraux::cbor_match_tagged_get_payload(c);
        cbor_det_view::Tagged { tag, payload }
    }
    else
    {
        let i: u8 =
            match c
            {
                crate::cbordetveraux::cbor_raw::CBOR_Case_Simple { v: res } => res,
                _ => panic!("Incomplete pattern matching")
            };
        cbor_det_view::SimpleValue { _0: i }
    }
}

pub fn cbor_det_get_array_length(x: crate::cbordetveraux::cbor_raw) -> u64
{
    let res: crate::cbordetveraux::raw_uint64 =
        match x
        {
            crate::cbordetveraux::cbor_raw::CBOR_Case_Array { v: c· } =>
              crate::cbordetveraux::raw_uint64
              { size: c·.cbor_array_length_size, value: (c·.cbor_array_ptr).len() as u64 },
            crate::cbordetveraux::cbor_raw::CBOR_Case_Serialized_Array { v: c· } =>
              c·.cbor_serialized_header,
            _ => panic!("Incomplete pattern matching")
        };
    res.value
}

pub type cbor_det_array_iterator_t <'a> =
crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>;

pub fn cbor_det_array_iterator_start <'a>(x: crate::cbordetveraux::cbor_raw <'a>) ->
    crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{ crate::cbordetveraux::cbor_array_iterator_init(x) }

pub fn cbor_det_array_iterator_is_empty(
    x: crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
) ->
    bool
{ crate::cbordetveraux::cbor_array_iterator_is_empty(x) }

pub fn cbor_det_array_iterator_next <'b, 'a>(
    x: &'b mut [crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>]
) ->
    crate::cbordetveraux::cbor_raw
    <'a>
{ crate::cbordetveraux::cbor_array_iterator_next(x) }

pub fn cbor_det_array_iterator_length(
    x: crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
) ->
    u64
{ crate::cbordetveraux::cbor_array_iterator_length(x) }

pub fn cbor_det_array_iterator_truncate <'a>(
    x: crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>,
    len: u64
) ->
    crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{ crate::cbordetveraux::cbor_array_iterator_truncate(x, len) }

pub fn cbor_det_get_array_item <'a>(x: crate::cbordetveraux::cbor_raw <'a>, i: u64) ->
    option__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    let len: u64 = cbor_det_get_array_length(x);
    if i >= len
    { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
    else
    {
        let res: crate::cbordetveraux::cbor_raw = crate::cbordetveraux::cbor_array_item(x, i);
        option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: res }
    }
}

pub fn cbor_det_map_length(x: crate::cbordetveraux::cbor_raw) -> u64
{
    let res: crate::cbordetveraux::raw_uint64 =
        match x
        {
            crate::cbordetveraux::cbor_raw::CBOR_Case_Map { v: c· } =>
              crate::cbordetveraux::raw_uint64
              { size: c·.cbor_map_length_size, value: (c·.cbor_map_ptr).len() as u64 },
            crate::cbordetveraux::cbor_raw::CBOR_Case_Serialized_Map { v: c· } =>
              c·.cbor_serialized_header,
            _ => panic!("Incomplete pattern matching")
        };
    res.value
}

pub type cbor_det_map_iterator_t <'a> =
crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>;

pub fn cbor_det_map_iterator_start <'a>(x: crate::cbordetveraux::cbor_raw <'a>) ->
    crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
    <'a>
{ crate::cbordetveraux::cbor_map_iterator_init(x) }

pub fn cbor_det_map_iterator_is_empty(
    x: crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
) ->
    bool
{ crate::cbordetveraux::cbor_map_iterator_is_empty(x) }

pub fn cbor_det_map_iterator_next <'b, 'a>(
    x: &'b mut [crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>]
) ->
    crate::cbordetveraux::cbor_map_entry
    <'a>
{ crate::cbordetveraux::cbor_map_iterator_next(x) }

pub fn cbor_det_map_entry_key <'a>(x2: crate::cbordetveraux::cbor_map_entry <'a>) ->
    crate::cbordetveraux::cbor_raw
    <'a>
{ x2.cbor_map_entry_key }

pub fn cbor_det_map_entry_value <'a>(x2: crate::cbordetveraux::cbor_map_entry <'a>) ->
    crate::cbordetveraux::cbor_raw
    <'a>
{ x2.cbor_map_entry_value }

pub fn cbor_det_map_get <'a>(
    x: crate::cbordetveraux::cbor_raw <'a>,
    k: crate::cbordetveraux::cbor_raw <'a>
) ->
    option__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    let mut dest: [crate::cbordetveraux::cbor_raw; 1] = [k; 1usize];
    let i: crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry =
        crate::cbordetveraux::cbor_map_iterator_init(x);
    let mut pi: [crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry; 1] =
        [i; 1usize];
    let mut pres: [option__CBOR_Pulse_Raw_Type_cbor_raw; 1] =
        [option__CBOR_Pulse_Raw_Type_cbor_raw::None; 1usize];
    let i_is_empty: bool = crate::cbordetveraux::cbor_map_iterator_is_empty(i);
    let cont: bool = ! i_is_empty;
    let mut pcont: [bool; 1] = [cont; 1usize];
    while
    (&pcont)[0usize]
    {
        let entry: crate::cbordetveraux::cbor_map_entry =
            crate::cbordetveraux::cbor_map_iterator_next(&mut pi);
        let key: crate::cbordetveraux::cbor_raw = entry.cbor_map_entry_key;
        let comp: i16 = crate::cbordetveraux::impl_cbor_det_compare(key, k);
        if comp == 0i16
        {
            let value: crate::cbordetveraux::cbor_raw = entry.cbor_map_entry_value;
            (&mut pres)[0usize] = option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: value };
            (&mut pcont)[0usize] = false
        }
        else if comp > 0i16
        { (&mut pcont)[0usize] = false }
        else
        {
            let i·: crate::cbordetveraux::cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry =
                (&pi)[0usize];
            let is_empty: bool = crate::cbordetveraux::cbor_map_iterator_is_empty(i·);
            let cont1: bool = ! is_empty;
            (&mut pcont)[0usize] = cont1
        }
    };
    let res: option__CBOR_Pulse_Raw_Type_cbor_raw = (&pres)[0usize];
    let bres: bool =
        match res
        {
            option__CBOR_Pulse_Raw_Type_cbor_raw::None => false,
            option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: vres } =>
              {
                  (&mut dest)[0usize] = vres;
                  true
              },
            _ => panic!("Incomplete pattern matching")
        };
    if bres
    {
        let res1: crate::cbordetveraux::cbor_raw = (&dest)[0usize];
        option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: res1 }
    }
    else
    { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
}

pub fn cbor_det_serialize_string(ty: u8, off: u64, out: &mut [u8]) -> usize
{
    let roff: crate::cbordetveraux::raw_uint64 = crate::cbordetveraux::mk_raw_uint64(off);
    crate::cbordetveraux::cbor_serialize_string(ty, roff, out)
}

pub fn cbor_det_serialize_tag(tag: u64, output: &mut [u8]) -> usize
{
    let tag·: crate::cbordetveraux::raw_uint64 = crate::cbordetveraux::mk_raw_uint64(tag);
    crate::cbordetveraux::cbor_serialize_tag(tag·, output)
}

pub fn cbor_det_serialize_array(len: u64, out: &mut [u8], off: usize) -> usize
{
    let rlen: crate::cbordetveraux::raw_uint64 = crate::cbordetveraux::mk_raw_uint64(len);
    crate::cbordetveraux::cbor_serialize_array(rlen, out, off)
}

pub fn cbor_det_serialize_map_insert(out: &mut [u8], off2: usize, off3: usize) -> bool
{ crate::cbordetveraux::cbor_raw_map_insert(out, off2, off3) }

pub fn cbor_det_serialize_map(len: u64, out: &mut [u8], off: usize) -> usize
{
    let rlen: crate::cbordetveraux::raw_uint64 = crate::cbordetveraux::mk_raw_uint64(len);
    crate::cbordetveraux::cbor_serialize_map(rlen, out, off)
}

pub fn dummy_cbor_det_t <'a>() -> crate::cbordetveraux::cbor_raw <'a>
{ crate::cbordetveraux::dummy_cbor_det_t() }
