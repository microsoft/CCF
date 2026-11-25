#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]
#![allow(unreachable_patterns)]

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_raw_serialized_iterator <'a>
{ pub s: &'a [u8], pub len: u64 }

#[derive(PartialEq, Clone, Copy)] pub struct raw_uint64 { pub size: u8, pub value: u64 }

fn get_bitfield_gen8(x: u8, lo: u32, hi: u32) -> u8
{
    let op1: u8 = x.wrapping_shl(8u32.wrapping_sub(hi));
    op1.wrapping_shr(8u32.wrapping_sub(hi).wrapping_add(lo))
}

fn set_bitfield_gen8(x: u8, lo: u32, hi: u32, v: u8) -> u8
{
    let op1: u8 = 255u8.wrapping_shr(8u32.wrapping_sub(hi.wrapping_sub(lo)));
    let op2: u8 = op1.wrapping_shl(lo);
    let op3: u8 = ! op2;
    let op4: u8 = x & op3;
    let op5: u8 = v.wrapping_shl(lo);
    op4 | op5
}

pub(crate) fn impl_correct(s: &[u8]) -> bool
{
    let mut pres: [bool; 1] = [true; 1usize];
    let mut pi: [usize; 1] = [0usize; 1usize];
    let len: usize = s.len();
    while
    true
    {
        let res: bool = (&pres)[0usize];
        let i: usize = (&pi)[0usize];
        if ! (res && i < len) { break };
        let i0: usize = (&pi)[0usize];
        let byte1: u8 = s[i0];
        let i1: usize = i0.wrapping_add(1usize);
        if byte1 <= 0x7fu8
        { (&mut pi)[0usize] = i1 }
        else if i1 == len
        { (&mut pres)[0usize] = false }
        else
        {
            let byte2: u8 = s[i1];
            let i2: usize = i1.wrapping_add(1usize);
            if 0xc2u8 <= byte1 && byte1 <= 0xdfu8 && (0x80u8 <= byte2 && byte2 <= 0xbfu8)
            { (&mut pi)[0usize] = i2 }
            else if i2 == len
            { (&mut pres)[0usize] = false }
            else
            {
                let byte3: u8 = s[i2];
                let i3: usize = i2.wrapping_add(1usize);
                if ! (0x80u8 <= byte3 && byte3 <= 0xbfu8)
                { (&mut pres)[0usize] = false }
                else if byte1 == 0xe0u8
                {
                    if 0xa0u8 <= byte2 && byte2 <= 0xbfu8
                    { (&mut pi)[0usize] = i3 }
                    else
                    { (&mut pres)[0usize] = false }
                }
                else if byte1 == 0xedu8
                {
                    if 0x80u8 <= byte2 && byte2 <= 0x9fu8
                    { (&mut pi)[0usize] = i3 }
                    else
                    { (&mut pres)[0usize] = false }
                }
                else if 0xe1u8 <= byte1 && byte1 <= 0xefu8 && (0x80u8 <= byte2 && byte2 <= 0xbfu8)
                { (&mut pi)[0usize] = i3 }
                else if i3 == len
                { (&mut pres)[0usize] = false }
                else
                {
                    let byte4: u8 = s[i3];
                    let i4: usize = i3.wrapping_add(1usize);
                    if ! (0x80u8 <= byte4 && byte4 <= 0xbfu8)
                    { (&mut pres)[0usize] = false }
                    else if byte1 == 0xf0u8 && 0x90u8 <= byte2 && byte2 <= 0xbfu8
                    { (&mut pi)[0usize] = i4 }
                    else if
                    0xf1u8 <= byte1 && byte1 < 0xf4u8 && (0x80u8 <= byte2 && byte2 <= 0xbfu8)
                    { (&mut pi)[0usize] = i4 }
                    else if byte1 == 0xf4u8 && 0x80u8 <= byte2 && byte2 <= 0x8fu8
                    { (&mut pi)[0usize] = i4 }
                    else
                    { (&mut pres)[0usize] = false }
                }
            }
        }
    };
    (&pres)[0usize]
}

#[derive(PartialEq, Clone, Copy)]
struct initial_byte_t
{ pub major_type: u8, pub additional_info: u8 }

const additional_info_long_argument_8_bits: u8 = 24u8;

const additional_info_unassigned_min: u8 = 28u8;

const additional_info_long_argument_16_bits: u8 = 25u8;

const additional_info_long_argument_32_bits: u8 = 26u8;

const additional_info_long_argument_64_bits: u8 = 27u8;

#[derive(PartialEq, Clone, Copy)]
enum long_argument_tags
{
    LongArgumentSimpleValue,
    LongArgumentU8,
    LongArgumentU16,
    LongArgumentU32,
    LongArgumentU64,
    LongArgumentOther
}

#[derive(PartialEq, Clone, Copy)]
enum long_argument
{
    LongArgumentSimpleValue { v: u8 },
    LongArgumentU8 { v: u8 },
    LongArgumentU16 { v: u16 },
    LongArgumentU32 { v: u32 },
    LongArgumentU64 { v: u64 },
    LongArgumentOther
}

fn argument_as_uint64(b: initial_byte_t, x: long_argument) -> u64
{
    match x
    {
        long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
        long_argument::LongArgumentU16 { v } => raw_uint64 { size: 2u8, value: v as u64 },
        long_argument::LongArgumentU32 { v } => raw_uint64 { size: 3u8, value: v as u64 },
        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
        long_argument::LongArgumentOther =>
          raw_uint64 { size: 0u8, value: b.additional_info as u64 },
        _ => panic!("Incomplete pattern matching")
    }.value
}

#[derive(PartialEq, Clone, Copy)]
struct dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
{ pub _1: initial_byte_t, pub _2: long_argument }

fn get_header_major_type(
    h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
) ->
    u8
{ h._1.major_type }

fn raw_uint64_as_argument(t: u8, x: raw_uint64) ->
    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
{
    if x.size == 0u8
    {
        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        {
            _1: initial_byte_t { major_type: t, additional_info: x.value as u8 },
            _2: long_argument::LongArgumentOther
        }
    }
    else if x.size == 1u8
    {
        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        {
            _1:
            initial_byte_t { major_type: t, additional_info: additional_info_long_argument_8_bits },
            _2: long_argument::LongArgumentU8 { v: x.value as u8 }
        }
    }
    else if x.size == 2u8
    {
        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        {
            _1:
            initial_byte_t { major_type: t, additional_info: additional_info_long_argument_16_bits },
            _2: long_argument::LongArgumentU16 { v: x.value as u16 }
        }
    }
    else if x.size == 3u8
    {
        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        {
            _1:
            initial_byte_t { major_type: t, additional_info: additional_info_long_argument_32_bits },
            _2: long_argument::LongArgumentU32 { v: x.value as u32 }
        }
    }
    else
    {
        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        {
            _1:
            initial_byte_t { major_type: t, additional_info: additional_info_long_argument_64_bits },
            _2: long_argument::LongArgumentU64 { v: x.value }
        }
    }
}

fn simple_value_as_argument(x: u8) ->
    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
{
    if x <= max_simple_value_additional_info
    {
        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        {
            _1: initial_byte_t { major_type: cbor_major_type_simple_value, additional_info: x },
            _2: long_argument::LongArgumentOther
        }
    }
    else
    {
        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        {
            _1:
            initial_byte_t
            {
                major_type: cbor_major_type_simple_value,
                additional_info: additional_info_long_argument_8_bits
            },
            _2: long_argument::LongArgumentSimpleValue { v: x }
        }
    }
}

fn read_initial_byte_t(input: &[u8]) -> initial_byte_t
{
    let x: u8 = input[0usize];
    initial_byte_t
    {
        major_type: get_bitfield_gen8(x, 5u32, 8u32),
        additional_info: get_bitfield_gen8(x, 0u32, 5u32)
    }
}

fn validate_header(input: &[u8], poffset: &mut [usize]) -> bool
{
    let offset: usize = poffset[0usize];
    let offset1: usize = poffset[0usize];
    let offset2: usize = poffset[0usize];
    let is_valid: bool =
        if input.len().wrapping_sub(offset2) < 1usize
        { false }
        else
        {
            poffset[0usize] = offset2.wrapping_add(1usize);
            true
        };
    let is_valid1: bool =
        if is_valid
        {
            let off: usize = poffset[0usize];
            let _letpattern: (&[u8], &[u8]) = input.split_at(offset1);
            let input·: &[u8] =
                {
                    let _input1: &[u8] = _letpattern.0;
                    let input23: &[u8] = _letpattern.1;
                    let consumed: usize = off.wrapping_sub(offset1);
                    let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                    let input2: &[u8] = _letpattern1.0;
                    let _input3: &[u8] = _letpattern1.1;
                    input2
                };
            let x: initial_byte_t = read_initial_byte_t(input·);
            (x.major_type != cbor_major_type_simple_value
            ||
            x.additional_info <= additional_info_long_argument_8_bits)
            &&
            x.additional_info < additional_info_unassigned_min
        }
        else
        { false };
    if is_valid1
    {
        let off: usize = poffset[0usize];
        let _letpattern: (&[u8], &[u8]) = input.split_at(offset);
        let input·: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input23: &[u8] = _letpattern.1;
                let consumed: usize = off.wrapping_sub(offset);
                let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern1.0;
                let _input3: &[u8] = _letpattern1.1;
                input2
            };
        let x: initial_byte_t = read_initial_byte_t(input·);
        if x.additional_info == additional_info_long_argument_8_bits
        {
            if x.major_type == cbor_major_type_simple_value
            {
                let offset3: usize = poffset[0usize];
                let offset4: usize = poffset[0usize];
                let is_valid2: bool =
                    if input.len().wrapping_sub(offset4) < 1usize
                    { false }
                    else
                    {
                        poffset[0usize] = offset4.wrapping_add(1usize);
                        true
                    };
                if is_valid2
                {
                    let off1: usize = poffset[0usize];
                    let _letpattern1: (&[u8], &[u8]) = input.split_at(offset3);
                    let input·1: &[u8] =
                        {
                            let _input1: &[u8] = _letpattern1.0;
                            let input23: &[u8] = _letpattern1.1;
                            let consumed: usize = off1.wrapping_sub(offset3);
                            let _letpattern2: (&[u8], &[u8]) = input23.split_at(consumed);
                            let input2: &[u8] = _letpattern2.0;
                            let _input3: &[u8] = _letpattern2.1;
                            input2
                        };
                    let x1: u8 = input·1[0usize];
                    min_simple_value_long_argument <= x1
                }
                else
                { false }
            }
            else
            {
                let offset3: usize = poffset[0usize];
                if input.len().wrapping_sub(offset3) < 1usize
                { false }
                else
                {
                    poffset[0usize] = offset3.wrapping_add(1usize);
                    true
                }
            }
        }
        else if x.additional_info == additional_info_long_argument_16_bits
        {
            let offset3: usize = poffset[0usize];
            if input.len().wrapping_sub(offset3) < 2usize
            { false }
            else
            {
                poffset[0usize] = offset3.wrapping_add(2usize);
                true
            }
        }
        else if x.additional_info == additional_info_long_argument_32_bits
        {
            let offset3: usize = poffset[0usize];
            if input.len().wrapping_sub(offset3) < 4usize
            { false }
            else
            {
                poffset[0usize] = offset3.wrapping_add(4usize);
                true
            }
        }
        else if x.additional_info == additional_info_long_argument_64_bits
        {
            let offset3: usize = poffset[0usize];
            if input.len().wrapping_sub(offset3) < 8usize
            { false }
            else
            {
                poffset[0usize] = offset3.wrapping_add(8usize);
                true
            }
        }
        else
        { true }
    }
    else
    { false }
}

fn read_header(input: &[u8]) ->
    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
{
    let _letpattern: (&[u8], &[u8]) = input.split_at(1usize);
    let input1: &[u8] = _letpattern.0;
    let input2: &[u8] = _letpattern.1;
    let x1: initial_byte_t = read_initial_byte_t(input1);
    let x2: long_argument =
        if x1.additional_info == additional_info_long_argument_8_bits
        {
            if x1.major_type == cbor_major_type_simple_value
            {
                let x: u8 = input2[0usize];
                long_argument::LongArgumentSimpleValue { v: x }
            }
            else
            {
                let x: u8 = input2[0usize];
                long_argument::LongArgumentU8 { v: x }
            }
        }
        else if x1.additional_info == additional_info_long_argument_16_bits
        {
            let last: u8 = input2[1usize];
            let last1: u8 = input2[0usize];
            let n: u16 = last1 as u16;
            let blast: u16 = last as u16;
            let x: u16 = blast.wrapping_add(n.wrapping_mul(256u16));
            long_argument::LongArgumentU16 { v: x }
        }
        else if x1.additional_info == additional_info_long_argument_32_bits
        {
            let last: u8 = input2[3usize];
            let pos·: usize = 3usize.wrapping_sub(1usize);
            let last1: u8 = input2[pos·];
            let pos·1: usize = pos·.wrapping_sub(1usize);
            let last2: u8 = input2[pos·1];
            let last3: u8 = input2[0usize];
            let n: u32 = last3 as u32;
            let blast: u32 = last2 as u32;
            let n1: u32 = blast.wrapping_add(n.wrapping_mul(256u32));
            let blast1: u32 = last1 as u32;
            let n2: u32 = blast1.wrapping_add(n1.wrapping_mul(256u32));
            let blast2: u32 = last as u32;
            let x: u32 = blast2.wrapping_add(n2.wrapping_mul(256u32));
            long_argument::LongArgumentU32 { v: x }
        }
        else if x1.additional_info == additional_info_long_argument_64_bits
        {
            let last: u8 = input2[7usize];
            let pos·: usize = 7usize.wrapping_sub(1usize);
            let last1: u8 = input2[pos·];
            let pos·1: usize = pos·.wrapping_sub(1usize);
            let last2: u8 = input2[pos·1];
            let pos·2: usize = pos·1.wrapping_sub(1usize);
            let last3: u8 = input2[pos·2];
            let pos·3: usize = pos·2.wrapping_sub(1usize);
            let last4: u8 = input2[pos·3];
            let pos·4: usize = pos·3.wrapping_sub(1usize);
            let last5: u8 = input2[pos·4];
            let pos·5: usize = pos·4.wrapping_sub(1usize);
            let last6: u8 = input2[pos·5];
            let last7: u8 = input2[0usize];
            let n: u64 = last7 as u64;
            let blast: u64 = last6 as u64;
            let n1: u64 = blast.wrapping_add(n.wrapping_mul(256u64));
            let blast1: u64 = last5 as u64;
            let n2: u64 = blast1.wrapping_add(n1.wrapping_mul(256u64));
            let blast2: u64 = last4 as u64;
            let n3: u64 = blast2.wrapping_add(n2.wrapping_mul(256u64));
            let blast3: u64 = last3 as u64;
            let n4: u64 = blast3.wrapping_add(n3.wrapping_mul(256u64));
            let blast4: u64 = last2 as u64;
            let n5: u64 = blast4.wrapping_add(n4.wrapping_mul(256u64));
            let blast5: u64 = last1 as u64;
            let n6: u64 = blast5.wrapping_add(n5.wrapping_mul(256u64));
            let blast6: u64 = last as u64;
            let x: u64 = blast6.wrapping_add(n6.wrapping_mul(256u64));
            long_argument::LongArgumentU64 { v: x }
        }
        else
        { long_argument::LongArgumentOther };
    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
    { _1: x1, _2: x2 }
}

fn jump_header(input: &[u8], offset: usize) -> usize
{
    let off1: usize = offset.wrapping_add(1usize);
    let _letpattern: (&[u8], &[u8]) = input.split_at(offset);
    let input·: &[u8] =
        {
            let _input1: &[u8] = _letpattern.0;
            let input23: &[u8] = _letpattern.1;
            let consumed: usize = off1.wrapping_sub(offset);
            let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
            let input2: &[u8] = _letpattern1.0;
            let _input3: &[u8] = _letpattern1.1;
            input2
        };
    let x: initial_byte_t = read_initial_byte_t(input·);
    if x.additional_info == additional_info_long_argument_8_bits
    { off1.wrapping_add(1usize) }
    else if x.additional_info == additional_info_long_argument_16_bits
    { off1.wrapping_add(2usize) }
    else if x.additional_info == additional_info_long_argument_32_bits
    { off1.wrapping_add(4usize) }
    else if x.additional_info == additional_info_long_argument_64_bits
    { off1.wrapping_add(8usize) }
    else
    { off1 }
}

fn validate_recursive_step_count_leaf(a: &[u8], bound: usize, prem: &mut [usize]) -> bool
{
    let i: usize = jump_header(a, 0usize);
    let _letpattern: (&[u8], &[u8]) = a.split_at(i);
    let input1: &[u8] = _letpattern.0;
    let _input2: &[u8] = _letpattern.1;
    let h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument =
        read_header(input1);
    let typ: u8 = get_header_major_type(h);
    if typ == cbor_major_type_array
    {
        let arg64: u64 = argument_as_uint64(h._1, h._2);
        let q1: usize = bound.wrapping_div(32768usize);
        let q2: usize = q1.wrapping_div(32768usize);
        let q3: usize = q2.wrapping_div(32768usize);
        let q4: usize = q3.wrapping_div(32768usize);
        let __anf0: bool =
            if q4 >= 16usize
            { true }
            else
            {
                let b64: u64 = bound as u64;
                arg64 <= b64
            };
        if __anf0
        {
            prem[0usize] = arg64 as usize;
            false
        }
        else
        { true }
    }
    else if typ == cbor_major_type_map
    {
        let arg64: u64 = argument_as_uint64(h._1, h._2);
        let q1: usize = bound.wrapping_div(32768usize);
        let q2: usize = q1.wrapping_div(32768usize);
        let q3: usize = q2.wrapping_div(32768usize);
        let q4: usize = q3.wrapping_div(32768usize);
        let __anf0: bool =
            if q4 >= 16usize
            { true }
            else
            {
                let b64: u64 = bound as u64;
                arg64 <= b64
            };
        if __anf0
        {
            let arg: usize = arg64 as usize;
            if bound.wrapping_sub(arg) < arg
            { true }
            else
            {
                prem[0usize] = arg.wrapping_add(arg);
                false
            }
        }
        else
        { true }
    }
    else if typ == cbor_major_type_tagged
    {
        prem[0usize] = 1usize;
        false
    }
    else
    {
        prem[0usize] = 0usize;
        false
    }
}

fn validate_raw_data_item(input: &[u8], poffset: &mut [usize]) -> bool
{
    let mut pn: [usize; 1] = [1usize; 1usize];
    let mut pres: [bool; 1] = [true; 1usize];
    while
    true
    {
        let res: bool = (&pres)[0usize];
        let n: usize = (&pn)[0usize];
        if ! (res && n > 0usize) { break };
        let off: usize = poffset[0usize];
        let n0: usize = (&pn)[0usize];
        if n0 > input.len().wrapping_sub(off)
        { (&mut pres)[0usize] = false }
        else
        {
            let offset: usize = poffset[0usize];
            let is_valid1: bool = validate_header(input, poffset);
            let res1: bool =
                if is_valid1
                {
                    let off1: usize = poffset[0usize];
                    let _letpattern: (&[u8], &[u8]) = input.split_at(offset);
                    let input·: &[u8] =
                        {
                            let _input1: &[u8] = _letpattern.0;
                            let input23: &[u8] = _letpattern.1;
                            let consumed: usize = off1.wrapping_sub(offset);
                            let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                            let input2: &[u8] = _letpattern1.0;
                            let _input3: &[u8] = _letpattern1.1;
                            input2
                        };
                    let
                    x:
                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                    =
                        read_header(input·);
                    let b: initial_byte_t = x._1;
                    if
                    b.major_type == cbor_major_type_byte_string
                    ||
                    b.major_type == cbor_major_type_text_string
                    {
                        let offset1: usize = poffset[0usize];
                        let offset2: usize = poffset[0usize];
                        let remaining: usize = input.len().wrapping_sub(offset2);
                        let q1: usize = remaining.wrapping_div(32768usize);
                        let q2: usize = q1.wrapping_div(32768usize);
                        let q3: usize = q2.wrapping_div(32768usize);
                        let q4: usize = q3.wrapping_div(32768usize);
                        let __anf0: bool =
                            if q4 >= 16usize
                            { true }
                            else
                            {
                                let b64: u64 = remaining as u64;
                                argument_as_uint64(x._1, x._2) <= b64
                            };
                        let is_valid: bool =
                            if __anf0
                            {
                                poffset[0usize] =
                                    offset2.wrapping_add(argument_as_uint64(x._1, x._2) as usize);
                                true
                            }
                            else
                            { false };
                        if is_valid
                        {
                            let off2: usize = poffset[0usize];
                            let _letpattern1: (&[u8], &[u8]) = input.split_at(offset1);
                            let x1: &[u8] =
                                {
                                    let _input1: &[u8] = _letpattern1.0;
                                    let input23: &[u8] = _letpattern1.1;
                                    let consumed: usize = off2.wrapping_sub(offset1);
                                    let _letpattern2: (&[u8], &[u8]) = input23.split_at(consumed);
                                    let input2: &[u8] = _letpattern2.0;
                                    let _input3: &[u8] = _letpattern2.1;
                                    input2
                                };
                            if get_header_major_type(x) == cbor_major_type_byte_string
                            { true }
                            else
                            { impl_correct(x1) }
                        }
                        else
                        { false }
                    }
                    else
                    { true }
                }
                else
                { false };
            if ! res1
            { (&mut pres)[0usize] = false }
            else
            {
                let offset1: usize = poffset[0usize];
                let _letpattern: (&[u8], &[u8]) = input.split_at(off);
                let input1: &[u8] =
                    {
                        let _input1: &[u8] = _letpattern.0;
                        let input23: &[u8] = _letpattern.1;
                        let consumed: usize = offset1.wrapping_sub(off);
                        let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                        let input2: &[u8] = _letpattern1.0;
                        let _input3: &[u8] = _letpattern1.1;
                        input2
                    };
                let bound: usize = input.len().wrapping_sub(off).wrapping_sub(n0);
                let res2: bool = validate_recursive_step_count_leaf(input1, bound, &mut pn);
                let count: usize = (&pn)[0usize];
                if res2 || count > bound
                { (&mut pres)[0usize] = false }
                else
                {
                    let n·: usize = n0.wrapping_sub(1usize).wrapping_add(count);
                    (&mut pn)[0usize] = n·
                }
            }
        }
    };
    (&pres)[0usize]
}

fn impl_remaining_data_items_header(
    h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
) ->
    usize
{
    let typ: u8 = get_header_major_type(h);
    if typ == cbor_major_type_array
    {
        let arg64: u64 = argument_as_uint64(h._1, h._2);
        arg64 as usize
    }
    else if typ == cbor_major_type_map
    {
        let arg64: u64 = argument_as_uint64(h._1, h._2);
        let arg: usize = arg64 as usize;
        arg.wrapping_add(arg)
    }
    else if typ == cbor_major_type_tagged { 1usize } else { 0usize }
}

fn jump_recursive_step_count_leaf(a: &[u8]) -> usize
{
    let i: usize = jump_header(a, 0usize);
    let _letpattern: (&[u8], &[u8]) = a.split_at(i);
    let input1: &[u8] = _letpattern.0;
    let _input2: &[u8] = _letpattern.1;
    let h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument =
        read_header(input1);
    impl_remaining_data_items_header(h)
}

fn jump_raw_data_item(input: &[u8], offset: usize) -> usize
{
    let mut poffset: [usize; 1] = [offset; 1usize];
    let mut pn: [usize; 1] = [1usize; 1usize];
    while
    true
    {
        let n: usize = (&pn)[0usize];
        if n <= 0usize { break };
        let off: usize = (&poffset)[0usize];
        let off1: usize = jump_header(input, off);
        let _letpattern: (&[u8], &[u8]) = input.split_at(off);
        let input·: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input23: &[u8] = _letpattern.1;
                let consumed: usize = off1.wrapping_sub(off);
                let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern1.0;
                let _input3: &[u8] = _letpattern1.1;
                input2
            };
        let
        x: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            read_header(input·);
        let b: initial_byte_t = x._1;
        let off11: usize =
            if
            b.major_type == cbor_major_type_byte_string
            ||
            b.major_type == cbor_major_type_text_string
            { off1.wrapping_add(argument_as_uint64(x._1, x._2) as usize) }
            else
            { off1 };
        (&mut poffset)[0usize] = off11;
        let _letpattern1: (&[u8], &[u8]) = input.split_at(off);
        let input1: &[u8] =
            {
                let _input1: &[u8] = _letpattern1.0;
                let input23: &[u8] = _letpattern1.1;
                let consumed: usize = off11.wrapping_sub(off);
                let _letpattern2: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern2.0;
                let _input3: &[u8] = _letpattern2.1;
                input2
            };
        let n0: usize = (&pn)[0usize];
        let unused: usize = input.len().wrapping_sub(off11);
        crate::lowstar::ignore::ignore::<usize>(unused);
        let count: usize = jump_recursive_step_count_leaf(input1);
        (&mut pn)[0usize] = n0.wrapping_sub(1usize).wrapping_add(count)
    };
    (&poffset)[0usize]
}

fn validate_raw_data_item_map_length_bounded(n: usize, input: &[u8], poffset: &mut [usize]) ->
    bool
{
    let mut pn: [usize; 1] = [1usize; 1usize];
    let mut pres: [bool; 1] = [true; 1usize];
    while
    true
    {
        let res: bool = (&pres)[0usize];
        let n1: usize = (&pn)[0usize];
        if ! (res && n1 > 0usize) { break };
        let off: usize = poffset[0usize];
        let n10: usize = (&pn)[0usize];
        if n10 > input.len().wrapping_sub(off)
        { (&mut pres)[0usize] = false }
        else
        {
            let offset: usize = poffset[0usize];
            let is_valid1: bool = validate_header(input, poffset);
            let res1: bool =
                if is_valid1
                {
                    let off1: usize = poffset[0usize];
                    let _letpattern: (&[u8], &[u8]) = input.split_at(offset);
                    let input·: &[u8] =
                        {
                            let _input1: &[u8] = _letpattern.0;
                            let input23: &[u8] = _letpattern.1;
                            let consumed: usize = off1.wrapping_sub(offset);
                            let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                            let input2: &[u8] = _letpattern1.0;
                            let _input3: &[u8] = _letpattern1.1;
                            input2
                        };
                    let
                    x:
                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                    =
                        read_header(input·);
                    let b: initial_byte_t = x._1;
                    if
                    b.major_type == cbor_major_type_byte_string
                    ||
                    b.major_type == cbor_major_type_text_string
                    {
                        let offset1: usize = poffset[0usize];
                        let offset2: usize = poffset[0usize];
                        let remaining: usize = input.len().wrapping_sub(offset2);
                        let q1: usize = remaining.wrapping_div(32768usize);
                        let q2: usize = q1.wrapping_div(32768usize);
                        let q3: usize = q2.wrapping_div(32768usize);
                        let q4: usize = q3.wrapping_div(32768usize);
                        let __anf0: bool =
                            if q4 >= 16usize
                            { true }
                            else
                            {
                                let b64: u64 = remaining as u64;
                                argument_as_uint64(x._1, x._2) <= b64
                            };
                        let is_valid: bool =
                            if __anf0
                            {
                                poffset[0usize] =
                                    offset2.wrapping_add(argument_as_uint64(x._1, x._2) as usize);
                                true
                            }
                            else
                            { false };
                        if is_valid
                        {
                            let off2: usize = poffset[0usize];
                            let _letpattern1: (&[u8], &[u8]) = input.split_at(offset1);
                            let x1: &[u8] =
                                {
                                    let _input1: &[u8] = _letpattern1.0;
                                    let input23: &[u8] = _letpattern1.1;
                                    let consumed: usize = off2.wrapping_sub(offset1);
                                    let _letpattern2: (&[u8], &[u8]) = input23.split_at(consumed);
                                    let input2: &[u8] = _letpattern2.0;
                                    let _input3: &[u8] = _letpattern2.1;
                                    input2
                                };
                            if get_header_major_type(x) == cbor_major_type_byte_string
                            { true }
                            else
                            { impl_correct(x1) }
                        }
                        else
                        { false }
                    }
                    else
                    { true }
                }
                else
                { false };
            if ! res1
            { (&mut pres)[0usize] = false }
            else
            {
                let offset1: usize = poffset[0usize];
                let _letpattern: (&[u8], &[u8]) = input.split_at(off);
                let input1: &[u8] =
                    {
                        let _input1: &[u8] = _letpattern.0;
                        let input23: &[u8] = _letpattern.1;
                        let consumed: usize = offset1.wrapping_sub(off);
                        let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                        let input2: &[u8] = _letpattern1.0;
                        let _input3: &[u8] = _letpattern1.1;
                        input2
                    };
                let i: usize = jump_header(input1, 0usize);
                let _letpattern1: (&[u8], &[u8]) = input1.split_at(i);
                let res_pred: bool =
                    {
                        let input11: &[u8] = _letpattern1.0;
                        let _input2: &[u8] = _letpattern1.1;
                        let
                        h:
                        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                        =
                            read_header(input11);
                        let typ: u8 = get_header_major_type(h);
                        if typ == cbor_major_type_map
                        {
                            let arg64: u64 = argument_as_uint64(h._1, h._2);
                            let q1: usize = n.wrapping_div(32768usize);
                            let q2: usize = q1.wrapping_div(32768usize);
                            let q3: usize = q2.wrapping_div(32768usize);
                            let q4: usize = q3.wrapping_div(32768usize);
                            if q4 >= 16usize
                            { true }
                            else
                            {
                                let b64: u64 = n as u64;
                                arg64 <= b64
                            }
                        }
                        else
                        { true }
                    };
                if ! res_pred
                { (&mut pres)[0usize] = false }
                else
                {
                    let bound: usize = input.len().wrapping_sub(off).wrapping_sub(n10);
                    let res2: bool = validate_recursive_step_count_leaf(input1, bound, &mut pn);
                    let count: usize = (&pn)[0usize];
                    if res2 || count > bound
                    { (&mut pres)[0usize] = false }
                    else
                    {
                        let n·: usize = n10.wrapping_sub(1usize).wrapping_add(count);
                        (&mut pn)[0usize] = n·
                    }
                }
            }
        }
    };
    (&pres)[0usize]
}

#[derive(PartialEq, Clone, Copy)]
enum option__size_t_tags
{
    None,
    Some
}

#[derive(PartialEq, Clone, Copy)]
pub enum option__size_t
{
    None,
    Some { v: usize }
}

pub(crate) fn validate_raw_data_item_nlist_bounded(
    map_length_bound: usize,
    map_key_bound: option__size_t,
    d: usize,
    n: usize,
    input: &[u8],
    poffset: &mut [usize]
) ->
    bool
{
    let mut pn: [usize; 1] = [n; 1usize];
    let mut pres: [bool; 1] = [true; 1usize];
    while
    true
    {
        let res: bool = (&pres)[0usize];
        let n1: usize = (&pn)[0usize];
        if ! (res && n1 > 0usize) { break };
        let off: usize = poffset[0usize];
        let n10: usize = (&pn)[0usize];
        if n10 > input.len().wrapping_sub(off)
        { (&mut pres)[0usize] = false }
        else
        {
            let offset: usize = poffset[0usize];
            let is_valid1: bool = validate_header(input, poffset);
            let res1: bool =
                if is_valid1
                {
                    let off1: usize = poffset[0usize];
                    let _letpattern: (&[u8], &[u8]) = input.split_at(offset);
                    let input·: &[u8] =
                        {
                            let _input1: &[u8] = _letpattern.0;
                            let input23: &[u8] = _letpattern.1;
                            let consumed: usize = off1.wrapping_sub(offset);
                            let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                            let input2: &[u8] = _letpattern1.0;
                            let _input3: &[u8] = _letpattern1.1;
                            input2
                        };
                    let
                    x:
                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                    =
                        read_header(input·);
                    let b: initial_byte_t = x._1;
                    if
                    b.major_type == cbor_major_type_byte_string
                    ||
                    b.major_type == cbor_major_type_text_string
                    {
                        let offset1: usize = poffset[0usize];
                        let offset2: usize = poffset[0usize];
                        let remaining: usize = input.len().wrapping_sub(offset2);
                        let q1: usize = remaining.wrapping_div(32768usize);
                        let q2: usize = q1.wrapping_div(32768usize);
                        let q3: usize = q2.wrapping_div(32768usize);
                        let q4: usize = q3.wrapping_div(32768usize);
                        let __anf0: bool =
                            if q4 >= 16usize
                            { true }
                            else
                            {
                                let b64: u64 = remaining as u64;
                                argument_as_uint64(x._1, x._2) <= b64
                            };
                        let is_valid: bool =
                            if __anf0
                            {
                                poffset[0usize] =
                                    offset2.wrapping_add(argument_as_uint64(x._1, x._2) as usize);
                                true
                            }
                            else
                            { false };
                        if is_valid
                        {
                            let off2: usize = poffset[0usize];
                            let _letpattern1: (&[u8], &[u8]) = input.split_at(offset1);
                            let x1: &[u8] =
                                {
                                    let _input1: &[u8] = _letpattern1.0;
                                    let input23: &[u8] = _letpattern1.1;
                                    let consumed: usize = off2.wrapping_sub(offset1);
                                    let _letpattern2: (&[u8], &[u8]) = input23.split_at(consumed);
                                    let input2: &[u8] = _letpattern2.0;
                                    let _input3: &[u8] = _letpattern2.1;
                                    input2
                                };
                            if get_header_major_type(x) == cbor_major_type_byte_string
                            { true }
                            else
                            { impl_correct(x1) }
                        }
                        else
                        { false }
                    }
                    else
                    { true }
                }
                else
                { false };
            if ! res1
            { (&mut pres)[0usize] = false }
            else
            {
                let offset1: usize = poffset[0usize];
                let _letpattern: (&[u8], &[u8]) = input.split_at(off);
                let input1: &[u8] =
                    {
                        let _input1: &[u8] = _letpattern.0;
                        let input23: &[u8] = _letpattern.1;
                        let consumed: usize = offset1.wrapping_sub(off);
                        let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                        let input2: &[u8] = _letpattern1.0;
                        let _input3: &[u8] = _letpattern1.1;
                        input2
                    };
                let bound: usize = input.len().wrapping_sub(off).wrapping_sub(n10);
                let i: usize = jump_header(input1, 0usize);
                let _letpattern1: (&[u8], &[u8]) = input1.split_at(i);
                let r: u8 =
                    {
                        let input11: &[u8] = _letpattern1.0;
                        let _input2: &[u8] = _letpattern1.1;
                        let
                        h:
                        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                        =
                            read_header(input11);
                        let typ: u8 = get_header_major_type(h);
                        if typ == cbor_major_type_array
                        {
                            let arg64: u64 = argument_as_uint64(h._1, h._2);
                            let q1: usize = bound.wrapping_div(32768usize);
                            let q2: usize = q1.wrapping_div(32768usize);
                            let q3: usize = q2.wrapping_div(32768usize);
                            let q4: usize = q3.wrapping_div(32768usize);
                            let __anf0: bool =
                                if q4 >= 16usize
                                { true }
                                else
                                {
                                    let b64: u64 = bound as u64;
                                    arg64 <= b64
                                };
                            if __anf0
                            {
                                (&mut pn)[0usize] = arg64 as usize;
                                2u8
                            }
                            else
                            { 1u8 }
                        }
                        else if typ == cbor_major_type_map
                        {
                            let arg64: u64 = argument_as_uint64(h._1, h._2);
                            let q1: usize = map_length_bound.wrapping_div(32768usize);
                            let q2: usize = q1.wrapping_div(32768usize);
                            let q3: usize = q2.wrapping_div(32768usize);
                            let q4: usize = q3.wrapping_div(32768usize);
                            let __anf0: bool =
                                if q4 >= 16usize
                                { true }
                                else
                                {
                                    let b64: u64 = map_length_bound as u64;
                                    arg64 <= b64
                                };
                            if ! __anf0
                            { 0u8 }
                            else
                            {
                                let q11: usize = bound.wrapping_div(32768usize);
                                let q21: usize = q11.wrapping_div(32768usize);
                                let q31: usize = q21.wrapping_div(32768usize);
                                let q41: usize = q31.wrapping_div(32768usize);
                                let __anf01: bool =
                                    if q41 >= 16usize
                                    { true }
                                    else
                                    {
                                        let b64: u64 = bound as u64;
                                        arg64 <= b64
                                    };
                                if __anf01
                                {
                                    let arg: usize = arg64 as usize;
                                    if bound.wrapping_sub(arg) < arg
                                    { 1u8 }
                                    else
                                    {
                                        (&mut pn)[0usize] = arg.wrapping_add(arg);
                                        3u8
                                    }
                                }
                                else
                                { 1u8 }
                            }
                        }
                        else if typ == cbor_major_type_tagged
                        {
                            (&mut pn)[0usize] = 1usize;
                            2u8
                        }
                        else
                        {
                            (&mut pn)[0usize] = 0usize;
                            2u8
                        }
                    };
                if r == 0u8
                { (&mut pres)[0usize] = false }
                else
                {
                    let count: usize = (&pn)[0usize];
                    if r == 1u8 || count > bound
                    { (&mut pres)[0usize] = false }
                    else if r == 3u8
                    {
                        if d == 0usize
                        { (&mut pres)[0usize] = false }
                        else
                        {
                            let d·: usize = d.wrapping_sub(1usize);
                            if
                            if d == 0usize
                            { 0usize }
                            else
                            {
                                match map_key_bound
                                {
                                    option__size_t::None => d.wrapping_sub(1usize),
                                    option__size_t::Some { v: k } =>
                                      if k < d.wrapping_sub(1usize)
                                      { k }
                                      else
                                      { d.wrapping_sub(1usize) },
                                    _ => panic!("Incomplete pattern matching")
                                }
                            }
                            ==
                            d·
                            {
                                let res3: bool =
                                    validate_raw_data_item_nlist_bounded(
                                        map_length_bound,
                                        map_key_bound,
                                        d·,
                                        count,
                                        input,
                                        poffset
                                    );
                                if ! res3
                                { (&mut pres)[0usize] = false }
                                else
                                { (&mut pn)[0usize] = n10.wrapping_sub(1usize) }
                            }
                            else
                            {
                                let mut pn1: [usize; 1] = [count; 1usize];
                                let mut pfirst: [bool; 1] = [true; 1usize];
                                let mut pres1: [bool; 1] = [true; 1usize];
                                while
                                true
                                {
                                    let res0: bool = (&pres1)[0usize];
                                    let n2: usize = (&pn1)[0usize];
                                    if ! (res0 && n2 > 0usize) { break };
                                    let n20: usize = (&pn1)[0usize];
                                    let first: bool = (&pfirst)[0usize];
                                    let dc: usize =
                                        if first
                                        {
                                            if d == 0usize
                                            { 0usize }
                                            else
                                            {
                                                match map_key_bound
                                                {
                                                    option__size_t::None => d.wrapping_sub(1usize),
                                                    option__size_t::Some { v: k } =>
                                                      if k < d.wrapping_sub(1usize)
                                                      { k }
                                                      else
                                                      { d.wrapping_sub(1usize) },
                                                    _ => panic!("Incomplete pattern matching")
                                                }
                                            }
                                        }
                                        else
                                        { d· };
                                    let res11: bool =
                                        validate_raw_data_item_nlist_bounded(
                                            map_length_bound,
                                            map_key_bound,
                                            dc,
                                            1usize,
                                            input,
                                            poffset
                                        );
                                    if ! res11
                                    { (&mut pres1)[0usize] = false }
                                    else
                                    {
                                        (&mut pn1)[0usize] = n20.wrapping_sub(1usize);
                                        (&mut pfirst)[0usize] = ! first
                                    }
                                };
                                let res3: bool = (&pres1)[0usize];
                                if ! res3
                                { (&mut pres)[0usize] = false }
                                else
                                { (&mut pn)[0usize] = n10.wrapping_sub(1usize) }
                            }
                        }
                    }
                    else
                    { (&mut pn)[0usize] = n10.wrapping_sub(1usize).wrapping_add(count) }
                }
            }
        }
    };
    (&pres)[0usize]
}

fn validate_raw_data_item_bounded(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: option__size_t,
    input: &[u8],
    poffset: &mut [usize]
) ->
    bool
{
    validate_raw_data_item_nlist_bounded(
        map_length_bound,
        map_key_bound,
        map_depth_bound,
        1usize,
        input,
        poffset
    )
}

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_int
{ pub cbor_int_type: u8, pub cbor_int_size: u8, pub cbor_int_value: u64 }

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_string <'a>
{ pub cbor_string_type: u8, pub cbor_string_size: u8, pub cbor_string_ptr: &'a [u8] }

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_tagged <'a>
{ pub cbor_tagged_tag: raw_uint64, pub cbor_tagged_ptr: &'a [cbor_raw <'a>] }

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_array <'a>
{ pub cbor_array_length_size: u8, pub cbor_array_ptr: &'a [cbor_raw <'a>] }

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_serialized <'a>
{ pub cbor_serialized_header: raw_uint64, pub cbor_serialized_payload: &'a [u8] }

#[derive(PartialEq, Clone, Copy)]
enum cbor_raw_tags
{
    CBOR_Case_Int,
    CBOR_Case_Simple,
    CBOR_Case_String,
    CBOR_Case_Tagged,
    CBOR_Case_Array,
    CBOR_Case_Map,
    CBOR_Case_Serialized_Tagged,
    CBOR_Case_Serialized_Array,
    CBOR_Case_Serialized_Map
}

#[derive(PartialEq, Clone, Copy)]
pub enum cbor_raw <'a>
{
    CBOR_Case_Int { v: cbor_int },
    CBOR_Case_Simple { v: u8 },
    CBOR_Case_String { v: cbor_string <'a> },
    CBOR_Case_Tagged { v: cbor_tagged <'a> },
    CBOR_Case_Array { v: cbor_array <'a> },
    CBOR_Case_Map { v: cbor_map <'a> },
    CBOR_Case_Serialized_Tagged { v: cbor_serialized <'a> },
    CBOR_Case_Serialized_Array { v: cbor_serialized <'a> },
    CBOR_Case_Serialized_Map { v: cbor_serialized <'a> }
}

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_map_entry <'a>
{ pub cbor_map_entry_key: cbor_raw <'a>, pub cbor_map_entry_value: cbor_raw <'a> }

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_map <'a>
{ pub cbor_map_length_size: u8, pub cbor_map_ptr: &'a [cbor_map_entry <'a>] }

#[derive(PartialEq, Clone, Copy)]
pub enum cbor_rawÂ· <'a>
{
    CBOR_Case_Int { v: cbor_int },
    CBOR_Case_Simple { v: u8 },
    CBOR_Case_String { v: cbor_string <'a> },
    CBOR_Case_Tagged { v: cbor_tagged <'a> },
    CBOR_Case_Array { v: cbor_array <'a> },
    CBOR_Case_Map { v: cbor_map <'a> },
    CBOR_Case_Serialized_Tagged { v: cbor_serialized <'a> },
    CBOR_Case_Serialized_Array { v: cbor_serialized <'a> },
    CBOR_Case_Serialized_Map { v: cbor_serialized <'a> }
}

#[derive(PartialEq, Clone, Copy)]
pub struct cbor_arrayÂ· <'a>
{ pub cbor_array_length_size: u8, pub cbor_array_ptr: &'a [cbor_raw <'a>] }

#[derive(PartialEq, Clone, Copy)]
pub enum cbor_rawÂ·Â· <'a>
{
    CBOR_Case_Int { v: cbor_int },
    CBOR_Case_Simple { v: u8 },
    CBOR_Case_String { v: cbor_string <'a> },
    CBOR_Case_Tagged { v: cbor_tagged <'a> },
    CBOR_Case_Array { v: cbor_array <'a> },
    CBOR_Case_Map { v: cbor_map <'a> },
    CBOR_Case_Serialized_Tagged { v: cbor_serialized <'a> },
    CBOR_Case_Serialized_Array { v: cbor_serialized <'a> },
    CBOR_Case_Serialized_Map { v: cbor_serialized <'a> }
}

fn cbor_read <'a>(input: &'a [u8]) -> cbor_raw <'a>
{
    let
    mut
    ph:
    [dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument; 1]
    =
        [dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
            {
                _1:
                initial_byte_t { major_type: cbor_major_type_simple_value, additional_info: 0u8 },
                _2: long_argument::LongArgumentOther
            };
            1usize];
    let i: usize = jump_header(input, 0usize);
    let _letpattern: (&[u8], &[u8]) = input.split_at(i);
    let pc: &[u8] =
        {
            let ph1: &[u8] = _letpattern.0;
            let outc: &[u8] = _letpattern.1;
            let
            h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
            =
                read_header(ph1);
            (&mut ph)[0usize] = h;
            outc
        };
    let h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument =
        (&ph)[0usize];
    let typ: u8 = h._1.major_type;
    if typ == cbor_major_type_uint64 || typ == cbor_major_type_neg_int64
    {
        let i1: raw_uint64 =
            match h._2
            {
                long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                long_argument::LongArgumentU16 { v } => raw_uint64 { size: 2u8, value: v as u64 },
                long_argument::LongArgumentU32 { v } => raw_uint64 { size: 3u8, value: v as u64 },
                long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                long_argument::LongArgumentOther =>
                  raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                _ => panic!("Incomplete pattern matching")
            };
        let resi: cbor_int =
            cbor_int { cbor_int_type: typ, cbor_int_size: i1.size, cbor_int_value: i1.value };
        cbor_raw::CBOR_Case_Int { v: resi }
    }
    else if typ == cbor_major_type_text_string || typ == cbor_major_type_byte_string
    {
        let i1: raw_uint64 =
            match h._2
            {
                long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                long_argument::LongArgumentU16 { v } => raw_uint64 { size: 2u8, value: v as u64 },
                long_argument::LongArgumentU32 { v } => raw_uint64 { size: 3u8, value: v as u64 },
                long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                long_argument::LongArgumentOther =>
                  raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                _ => panic!("Incomplete pattern matching")
            };
        let ress: cbor_string =
            cbor_string { cbor_string_type: typ, cbor_string_size: i1.size, cbor_string_ptr: pc };
        cbor_raw::CBOR_Case_String { v: ress }
    }
    else if typ == cbor_major_type_tagged
    {
        let tag: raw_uint64 =
            match h._2
            {
                long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                long_argument::LongArgumentU16 { v } => raw_uint64 { size: 2u8, value: v as u64 },
                long_argument::LongArgumentU32 { v } => raw_uint64 { size: 3u8, value: v as u64 },
                long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                long_argument::LongArgumentOther =>
                  raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                _ => panic!("Incomplete pattern matching")
            };
        let rest: cbor_serialized =
            cbor_serialized { cbor_serialized_header: tag, cbor_serialized_payload: pc };
        cbor_raw::CBOR_Case_Serialized_Tagged { v: rest }
    }
    else if typ == cbor_major_type_array
    {
        let len: raw_uint64 =
            match h._2
            {
                long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                long_argument::LongArgumentU16 { v } => raw_uint64 { size: 2u8, value: v as u64 },
                long_argument::LongArgumentU32 { v } => raw_uint64 { size: 3u8, value: v as u64 },
                long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                long_argument::LongArgumentOther =>
                  raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                _ => panic!("Incomplete pattern matching")
            };
        let resa: cbor_serialized =
            cbor_serialized { cbor_serialized_header: len, cbor_serialized_payload: pc };
        cbor_raw::CBOR_Case_Serialized_Array { v: resa }
    }
    else if typ == cbor_major_type_map
    {
        let len: raw_uint64 =
            match h._2
            {
                long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                long_argument::LongArgumentU16 { v } => raw_uint64 { size: 2u8, value: v as u64 },
                long_argument::LongArgumentU32 { v } => raw_uint64 { size: 3u8, value: v as u64 },
                long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                long_argument::LongArgumentOther =>
                  raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                _ => panic!("Incomplete pattern matching")
            };
        let resa: cbor_serialized =
            cbor_serialized { cbor_serialized_header: len, cbor_serialized_payload: pc };
        cbor_raw::CBOR_Case_Serialized_Map { v: resa }
    }
    else
    {
        let i1: u8 =
            match h._2
            {
                long_argument::LongArgumentOther => h._1.additional_info,
                long_argument::LongArgumentSimpleValue { v } => v,
                _ => panic!("Incomplete pattern matching")
            };
        cbor_raw::CBOR_Case_Simple { v: i1 }
    }
}

fn cbor_parse <'a>(input: &'a [u8], len: usize) -> cbor_raw <'a>
{
    let _letpattern: (&[u8], &[u8]) = input.split_at(0usize);
    let input1: &[u8] =
        {
            let _input1: &[u8] = _letpattern.0;
            let input23: &[u8] = _letpattern.1;
            let consumed: usize = len.wrapping_sub(0usize);
            let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
            let input2: &[u8] = _letpattern1.0;
            let _input3: &[u8] = _letpattern1.1;
            input2
        };
    cbor_read(input1)
}

fn cbor_match_serialized_tagged_get_payload <'a>(c: cbor_serialized <'a>) -> cbor_raw <'a>
{ cbor_read(c.cbor_serialized_payload) }

fn cbor_serialized_array_iterator_init <'a>(c: cbor_serialized <'a>) ->
    cbor_raw_serialized_iterator
    <'a>
{
    cbor_raw_serialized_iterator
    { s: c.cbor_serialized_payload, len: c.cbor_serialized_header.value }
}

fn cbor_serialized_array_iterator_is_empty(c: cbor_raw_serialized_iterator) -> bool
{ c.len == 0u64 }

#[derive(PartialEq, Clone, Copy)]
enum cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw_tags
{
    CBOR_Raw_Iterator_Slice,
    CBOR_Raw_Iterator_Serialized
}

#[derive(PartialEq, Clone, Copy)]
pub enum cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>
{
    CBOR_Raw_Iterator_Slice { _0: &'a [cbor_raw <'a>] },
    CBOR_Raw_Iterator_Serialized { _0: cbor_raw_serialized_iterator <'a> }
}

fn cbor_serialized_array_iterator_next_with_depth <'b, 'a>(
    pi: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>],
    i: cbor_raw_serialized_iterator <'a>
) ->
    cbor_raw
    <'a>
{
    let i1: usize = jump_raw_data_item(i.s, 0usize);
    let _letpattern: (&[u8], &[u8]) = (i.s).split_at(i1);
    let s1: &[u8] = _letpattern.0;
    let s2: &[u8] = _letpattern.1;
    let res: cbor_raw = cbor_read(s1);
    let i·: cbor_raw_serialized_iterator =
        cbor_raw_serialized_iterator { s: s2, len: (i.len).wrapping_sub(1u64) };
    pi[0usize] =
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized { _0: i· };
    res
}

fn cbor_serialized_map_iterator_init <'a>(c: cbor_serialized <'a>) ->
    cbor_raw_serialized_iterator
    <'a>
{
    cbor_raw_serialized_iterator
    { s: c.cbor_serialized_payload, len: c.cbor_serialized_header.value }
}

fn cbor_serialized_map_iterator_is_empty(c: cbor_raw_serialized_iterator) -> bool
{ c.len == 0u64 }

#[derive(PartialEq, Clone, Copy)]
pub enum cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>
{
    CBOR_Raw_Iterator_Slice { _0: &'a [cbor_map_entry <'a>] },
    CBOR_Raw_Iterator_Serialized { _0: cbor_raw_serialized_iterator <'a> }
}

fn cbor_serialized_map_iterator_next_with_depth <'b, 'a>(
    pi: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>],
    i: cbor_raw_serialized_iterator <'a>
) ->
    cbor_map_entry
    <'a>
{
    let off1: usize = jump_raw_data_item(i.s, 0usize);
    let i1: usize = jump_raw_data_item(i.s, off1);
    let _letpattern: (&[u8], &[u8]) = (i.s).split_at(i1);
    let s1: &[u8] = _letpattern.0;
    let s2: &[u8] = _letpattern.1;
    let i2: usize = jump_raw_data_item(s1, 0usize);
    let _letpattern1: (&[u8], &[u8]) = s1.split_at(i2);
    let res: cbor_map_entry =
        {
            let s11: &[u8] = _letpattern1.0;
            let s21: &[u8] = _letpattern1.1;
            let res1: cbor_raw = cbor_read(s11);
            let res2: cbor_raw = cbor_read(s21);
            cbor_map_entry { cbor_map_entry_key: res1, cbor_map_entry_value: res2 }
        };
    let i·: cbor_raw_serialized_iterator =
        cbor_raw_serialized_iterator { s: s2, len: (i.len).wrapping_sub(1u64) };
    pi[0usize] =
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Serialized
        { _0: i· };
    res
}

fn cbor_serialized_array_iterator_next <'b, 'a>(
    pi: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>],
    i: cbor_raw_serialized_iterator <'a>
) ->
    cbor_raw
    <'a>
{
    let i1: usize = jump_raw_data_item(i.s, 0usize);
    let _letpattern: (&[u8], &[u8]) = (i.s).split_at(i1);
    let s1: &[u8] = _letpattern.0;
    let s2: &[u8] = _letpattern.1;
    let res: cbor_raw = cbor_read(s1);
    let i·: cbor_raw_serialized_iterator =
        cbor_raw_serialized_iterator { s: s2, len: (i.len).wrapping_sub(1u64) };
    pi[0usize] =
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized { _0: i· };
    res
}

fn cbor_serialized_array_iterator_length(c: cbor_raw_serialized_iterator) -> u64 { c.len }

fn cbor_serialized_array_iterator_truncate <'a>(c: cbor_raw_serialized_iterator <'a>, len: u64) ->
    cbor_raw_serialized_iterator
    <'a>
{ cbor_raw_serialized_iterator { s: c.s, len } }

fn cbor_serialized_array_item <'a>(c: cbor_serialized <'a>, i: u64) -> cbor_raw <'a>
{
    let j: usize = i as usize;
    let mut pi: [usize; 1] = [0usize; 1usize];
    let mut pres: [&[u8]; 1] = [c.cbor_serialized_payload; 1usize];
    while
    true
    {
        let i1: usize = (&pi)[0usize];
        if i1 >= j { break };
        let res: &[u8] = (&pres)[0usize];
        let i10: usize = (&pi)[0usize];
        let i2: usize = jump_raw_data_item(res, 0usize);
        let _letpattern: (&[u8], &[u8]) = res.split_at(i2);
        let res2: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input2: &[u8] = _letpattern.1;
                input2
            };
        (&mut pi)[0usize] = i10.wrapping_add(1usize);
        (&mut pres)[0usize] = res2
    };
    let res: &[u8] = (&pres)[0usize];
    let i1: usize = jump_raw_data_item(res, 0usize);
    let _letpattern: (&[u8], &[u8]) = res.split_at(i1);
    let elt: &[u8] =
        {
            let input1: &[u8] = _letpattern.0;
            let _input2: &[u8] = _letpattern.1;
            input1
        };
    cbor_read(elt)
}

fn cbor_serialized_map_iterator_next <'b, 'a>(
    pi: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>],
    i: cbor_raw_serialized_iterator <'a>
) ->
    cbor_map_entry
    <'a>
{
    let off1: usize = jump_raw_data_item(i.s, 0usize);
    let i1: usize = jump_raw_data_item(i.s, off1);
    let _letpattern: (&[u8], &[u8]) = (i.s).split_at(i1);
    let s1: &[u8] = _letpattern.0;
    let s2: &[u8] = _letpattern.1;
    let i2: usize = jump_raw_data_item(s1, 0usize);
    let _letpattern1: (&[u8], &[u8]) = s1.split_at(i2);
    let res: cbor_map_entry =
        {
            let s11: &[u8] = _letpattern1.0;
            let s21: &[u8] = _letpattern1.1;
            let res1: cbor_raw = cbor_read(s11);
            let res2: cbor_raw = cbor_read(s21);
            cbor_map_entry { cbor_map_entry_key: res1, cbor_map_entry_value: res2 }
        };
    let i·: cbor_raw_serialized_iterator =
        cbor_raw_serialized_iterator { s: s2, len: (i.len).wrapping_sub(1u64) };
    pi[0usize] =
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Serialized
        { _0: i· };
    res
}

fn cbor_match_tagged_get_payload_with_depth <'a>(c: cbor_raw <'a>) -> cbor_raw <'a>
{
    match c
    {
        cbor_raw::CBOR_Case_Serialized_Tagged { v: cs } =>
          cbor_match_serialized_tagged_get_payload(cs),
        cbor_raw::CBOR_Case_Tagged { v: ct } => ct.cbor_tagged_ptr[0usize],
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_array_iterator_init_with_depth <'a>(c: cbor_raw <'a>) ->
    cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    match c
    {
        cbor_raw::CBOR_Case_Serialized_Array { v: c· } =>
          {
              let i·: cbor_raw_serialized_iterator = cbor_serialized_array_iterator_init(c·);
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized
              { _0: i· }
          },
        cbor_raw::CBOR_Case_Array { v: c· } =>
          {
              let i: &[cbor_raw] = c·.cbor_array_ptr;
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: i }
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_array_iterator_is_empty_with_depth(c: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw) ->
    bool
{
    match c
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: c· } =>
          c·.len() == 0usize,
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized { _0: c· } =>
          cbor_serialized_array_iterator_is_empty(c·),
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_array_iterator_next_with_depth <'b, 'a>(
    pi: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>]
) ->
    cbor_raw
    <'a>
{
    let iter: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw = pi[0usize];
    match iter
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: i } =>
          {
              let res: cbor_raw = i[0usize];
              let _letpattern: (&[cbor_raw], &[cbor_raw]) = i.split_at(1usize);
              let s·: &[cbor_raw] =
                  {
                      let _s1: &[cbor_raw] = _letpattern.0;
                      let s2: &[cbor_raw] = _letpattern.1;
                      s2
                  };
              pi[0usize] =
                  cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice
                  { _0: s· };
              res
          },
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized { _0: i } =>
          cbor_serialized_array_iterator_next_with_depth(pi, i),
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_map_iterator_init_with_depth <'a>(c: cbor_raw <'a>) ->
    cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
    <'a>
{
    match c
    {
        cbor_raw::CBOR_Case_Serialized_Map { v: c· } =>
          {
              let i·: cbor_raw_serialized_iterator = cbor_serialized_map_iterator_init(c·);
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Serialized
              { _0: i· }
          },
        cbor_raw::CBOR_Case_Map { v: c· } =>
          {
              let i: &[cbor_map_entry] = c·.cbor_map_ptr;
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Slice
              { _0: i }
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_map_iterator_is_empty_with_depth(
    c: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
) ->
    bool
{
    match c
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Slice
        { _0: c· }
        => c·.len() == 0usize,
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Serialized
        { _0: c· }
        => cbor_serialized_map_iterator_is_empty(c·),
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_map_iterator_next_with_depth <'b, 'a>(
    pi: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>]
) ->
    cbor_map_entry
    <'a>
{
    let iter: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry = pi[0usize];
    match iter
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Slice { _0: i } =>
          {
              let res: cbor_map_entry = i[0usize];
              let _letpattern: (&[cbor_map_entry], &[cbor_map_entry]) = i.split_at(1usize);
              let s·: &[cbor_map_entry] =
                  {
                      let _s1: &[cbor_map_entry] = _letpattern.0;
                      let s2: &[cbor_map_entry] = _letpattern.1;
                      s2
                  };
              pi[0usize] =
                  cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Slice
                  { _0: s· };
              res
          },
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Serialized
        { _0: i }
        => cbor_serialized_map_iterator_next_with_depth(pi, i),
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_match_tagged_get_payload <'a>(c: cbor_raw <'a>) -> cbor_raw <'a>
{
    match c
    {
        cbor_raw::CBOR_Case_Serialized_Tagged { v: cs } =>
          cbor_match_serialized_tagged_get_payload(cs),
        cbor_raw::CBOR_Case_Tagged { v: ct } => ct.cbor_tagged_ptr[0usize],
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_array_iterator_init <'a>(c: cbor_raw <'a>) ->
    cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    match c
    {
        cbor_raw::CBOR_Case_Serialized_Array { v: c· } =>
          {
              let i·: cbor_raw_serialized_iterator = cbor_serialized_array_iterator_init(c·);
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized
              { _0: i· }
          },
        cbor_raw::CBOR_Case_Array { v: c· } =>
          {
              let i: &[cbor_raw] = c·.cbor_array_ptr;
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: i }
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_array_iterator_is_empty(c: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw) -> bool
{
    match c
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: c· } =>
          c·.len() == 0usize,
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized { _0: c· } =>
          cbor_serialized_array_iterator_is_empty(c·),
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_array_iterator_next <'b, 'a>(
    pi: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>]
) ->
    cbor_raw
    <'a>
{
    let iter: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw = pi[0usize];
    match iter
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: i } =>
          {
              let res: cbor_raw = i[0usize];
              let _letpattern: (&[cbor_raw], &[cbor_raw]) = i.split_at(1usize);
              let s·: &[cbor_raw] =
                  {
                      let _s1: &[cbor_raw] = _letpattern.0;
                      let s2: &[cbor_raw] = _letpattern.1;
                      s2
                  };
              pi[0usize] =
                  cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice
                  { _0: s· };
              res
          },
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized { _0: i } =>
          cbor_serialized_array_iterator_next(pi, i),
        _ => panic!("Incomplete pattern matching")
    }
}

pub(crate) fn cbor_array_iterator_length(c: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw) ->
    u64
{
    match c
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: c· } =>
          c·.len() as u64,
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized { _0: c· } =>
          cbor_serialized_array_iterator_length(c·),
        _ => panic!("Incomplete pattern matching")
    }
}

pub(crate) fn cbor_array_iterator_truncate <'a>(
    c: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>,
    len: u64
) ->
    cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    match c
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: c· } =>
          {
              let _letpattern: (&[cbor_raw], &[cbor_raw]) = c·.split_at(len as usize);
              let sl1: &[cbor_raw] = _letpattern.0;
              let _sl2: &[cbor_raw] = _letpattern.1;
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Slice { _0: sl1 }
          },
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized { _0: c· } =>
          {
              let sres: cbor_raw_serialized_iterator =
                  cbor_serialized_array_iterator_truncate(c·, len);
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw::CBOR_Raw_Iterator_Serialized
              { _0: sres }
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_array_item <'a>(c: cbor_raw <'a>, i: u64) -> cbor_raw <'a>
{
    match c
    {
        cbor_raw::CBOR_Case_Serialized_Array { v: c· } => cbor_serialized_array_item(c·, i),
        cbor_raw::CBOR_Case_Array { v: c· } => c·.cbor_array_ptr[i as usize],
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_map_iterator_init <'a>(c: cbor_raw <'a>) ->
    cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
    <'a>
{
    match c
    {
        cbor_raw::CBOR_Case_Serialized_Map { v: c· } =>
          {
              let i·: cbor_raw_serialized_iterator = cbor_serialized_map_iterator_init(c·);
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Serialized
              { _0: i· }
          },
        cbor_raw::CBOR_Case_Map { v: c· } =>
          {
              let i: &[cbor_map_entry] = c·.cbor_map_ptr;
              cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Slice
              { _0: i }
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_map_iterator_is_empty(c: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry) -> bool
{
    match c
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Slice
        { _0: c· }
        => c·.len() == 0usize,
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Serialized
        { _0: c· }
        => cbor_serialized_map_iterator_is_empty(c·),
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_map_iterator_next <'b, 'a>(
    pi: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>]
) ->
    cbor_map_entry
    <'a>
{
    let iter: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry = pi[0usize];
    match iter
    {
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Slice { _0: i } =>
          {
              let res: cbor_map_entry = i[0usize];
              let _letpattern: (&[cbor_map_entry], &[cbor_map_entry]) = i.split_at(1usize);
              let s·: &[cbor_map_entry] =
                  {
                      let _s1: &[cbor_map_entry] = _letpattern.0;
                      let s2: &[cbor_map_entry] = _letpattern.1;
                      s2
                  };
              pi[0usize] =
                  cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Slice
                  { _0: s· };
              res
          },
        cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry::CBOR_Raw_Iterator_Serialized
        { _0: i }
        => cbor_serialized_map_iterator_next(pi, i),
        _ => panic!("Incomplete pattern matching")
    }
}

fn mk_raw_uint64(x: u64) -> raw_uint64
{
    let size: u8 =
        if x <= max_simple_value_additional_info as u64
        { 0u8 }
        else if x < 256u64
        { 1u8 }
        else if x < 65536u64 { 2u8 } else if x < 4294967296u64 { 3u8 } else { 4u8 };
    raw_uint64 { size, value: x }
}

fn impl_major_type(x: cbor_raw) -> u8
{
    match x
    {
        cbor_raw::CBOR_Case_Simple { .. } => cbor_major_type_simple_value,
        cbor_raw::CBOR_Case_Int { .. } =>
          match x
          {
              cbor_raw::CBOR_Case_Int { v: c· } => c·.cbor_int_type,
              _ => panic!("Incomplete pattern matching")
          },
        cbor_raw::CBOR_Case_String { .. } =>
          match x
          {
              cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_type,
              _ => panic!("Incomplete pattern matching")
          },
        cbor_raw::CBOR_Case_Tagged { .. } => cbor_major_type_tagged,
        cbor_raw::CBOR_Case_Serialized_Tagged { .. } => cbor_major_type_tagged,
        cbor_raw::CBOR_Case_Array { .. } => cbor_major_type_array,
        cbor_raw::CBOR_Case_Serialized_Array { .. } => cbor_major_type_array,
        cbor_raw::CBOR_Case_Map { .. } => cbor_major_type_map,
        cbor_raw::CBOR_Case_Serialized_Map { .. } => cbor_major_type_map,
        _ => panic!("Incomplete pattern matching")
    }
}

fn compute_deep(c: cbor_raw) -> bool
{
    match c
    {
        cbor_raw::CBOR_Case_Tagged { .. } => true,
        cbor_raw::CBOR_Case_Array { v: a } => (a.cbor_array_ptr).len() != 0usize,
        cbor_raw::CBOR_Case_Map { v: a } => (a.cbor_map_ptr).len() != 0usize,
        _ => false
    }
}

fn cbor_match_tagged_get_tag_with_depth(c: cbor_raw) -> raw_uint64
{
    match c
    {
        cbor_raw::CBOR_Case_Tagged { v: a } => a.cbor_tagged_tag,
        cbor_raw::CBOR_Case_Serialized_Tagged { .. } =>
          match c
          {
              cbor_raw::CBOR_Case_Tagged { v: c· } => c·.cbor_tagged_tag,
              cbor_raw::CBOR_Case_Serialized_Tagged { v: c· } => c·.cbor_serialized_header,
              _ => panic!("Incomplete pattern matching")
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_match_array_get_length_with_depth(c: cbor_raw) -> raw_uint64
{
    match c
    {
        cbor_raw::CBOR_Case_Array { v: a } =>
          raw_uint64 { size: a.cbor_array_length_size, value: (a.cbor_array_ptr).len() as u64 },
        cbor_raw::CBOR_Case_Serialized_Array { .. } =>
          match c
          {
              cbor_raw::CBOR_Case_Array { v: c· } =>
                raw_uint64
                { size: c·.cbor_array_length_size, value: (c·.cbor_array_ptr).len() as u64 },
              cbor_raw::CBOR_Case_Serialized_Array { v: c· } => c·.cbor_serialized_header,
              _ => panic!("Incomplete pattern matching")
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_match_map_get_length_with_depth(c: cbor_raw) -> raw_uint64
{
    match c
    {
        cbor_raw::CBOR_Case_Map { v: a } =>
          raw_uint64 { size: a.cbor_map_length_size, value: (a.cbor_map_ptr).len() as u64 },
        cbor_raw::CBOR_Case_Serialized_Map { .. } =>
          match c
          {
              cbor_raw::CBOR_Case_Map { v: c· } =>
                raw_uint64
                { size: c·.cbor_map_length_size, value: (c·.cbor_map_ptr).len() as u64 },
              cbor_raw::CBOR_Case_Serialized_Map { v: c· } => c·.cbor_serialized_header,
              _ => panic!("Incomplete pattern matching")
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_raw_get_header_d(xl: cbor_raw) ->
    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
{
    match xl
    {
        cbor_raw::CBOR_Case_Int { .. } =>
          {
              let ty: u8 =
                  match xl
                  {
                      cbor_raw::CBOR_Case_Int { v: c· } => c·.cbor_int_type,
                      _ => panic!("Incomplete pattern matching")
                  };
              let v: raw_uint64 =
                  match xl
                  {
                      cbor_raw::CBOR_Case_Int { v: c· } =>
                        raw_uint64 { size: c·.cbor_int_size, value: c·.cbor_int_value },
                      _ => panic!("Incomplete pattern matching")
                  };
              raw_uint64_as_argument(ty, v)
          },
        cbor_raw::CBOR_Case_String { .. } =>
          {
              let ty: u8 =
                  match xl
                  {
                      cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_type,
                      _ => panic!("Incomplete pattern matching")
                  };
              let len: raw_uint64 =
                  match xl
                  {
                      cbor_raw::CBOR_Case_String { v: c· } =>
                        raw_uint64
                        { size: c·.cbor_string_size, value: (c·.cbor_string_ptr).len() as u64 },
                      _ => panic!("Incomplete pattern matching")
                  };
              raw_uint64_as_argument(ty, len)
          },
        cbor_raw::CBOR_Case_Tagged { .. } =>
          {
              let tag: raw_uint64 = cbor_match_tagged_get_tag_with_depth(xl);
              raw_uint64_as_argument(cbor_major_type_tagged, tag)
          },
        cbor_raw::CBOR_Case_Serialized_Tagged { .. } =>
          {
              let tag: raw_uint64 = cbor_match_tagged_get_tag_with_depth(xl);
              raw_uint64_as_argument(cbor_major_type_tagged, tag)
          },
        cbor_raw::CBOR_Case_Array { .. } =>
          {
              let len: raw_uint64 = cbor_match_array_get_length_with_depth(xl);
              raw_uint64_as_argument(cbor_major_type_array, len)
          },
        cbor_raw::CBOR_Case_Serialized_Array { .. } =>
          {
              let len: raw_uint64 = cbor_match_array_get_length_with_depth(xl);
              raw_uint64_as_argument(cbor_major_type_array, len)
          },
        cbor_raw::CBOR_Case_Map { .. } =>
          {
              let len: raw_uint64 = cbor_match_map_get_length_with_depth(xl);
              raw_uint64_as_argument(cbor_major_type_map, len)
          },
        cbor_raw::CBOR_Case_Serialized_Map { .. } =>
          {
              let len: raw_uint64 = cbor_match_map_get_length_with_depth(xl);
              raw_uint64_as_argument(cbor_major_type_map, len)
          },
        cbor_raw::CBOR_Case_Simple { .. } =>
          {
              let v: u8 =
                  match xl
                  {
                      cbor_raw::CBOR_Case_Simple { v: res } => res,
                      _ => panic!("Incomplete pattern matching")
                  };
              simple_value_as_argument(v)
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_raw_with_perm_get_header_d(xl: cbor_raw) ->
    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
{ cbor_raw_get_header_d(xl) }

fn dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
    t: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
) ->
    initial_byte_t
{ t._1 }

fn size_header(
    x: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument,
    out: &mut [usize]
) ->
    bool
{
    let xh1: initial_byte_t =
        dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(x);
    let capacity: usize = out[0usize];
    let res1: bool =
        if capacity < 1usize
        { false }
        else
        {
            out[0usize] = capacity.wrapping_sub(1usize);
            true
        };
    if res1
    {
        if xh1.additional_info == additional_info_long_argument_8_bits
        {
            let capacity1: usize = out[0usize];
            if capacity1 < 1usize
            { false }
            else
            {
                out[0usize] = capacity1.wrapping_sub(1usize);
                true
            }
        }
        else if xh1.additional_info == additional_info_long_argument_16_bits
        {
            let capacity1: usize = out[0usize];
            if capacity1 < 2usize
            { false }
            else
            {
                out[0usize] = capacity1.wrapping_sub(2usize);
                true
            }
        }
        else if xh1.additional_info == additional_info_long_argument_32_bits
        {
            let capacity1: usize = out[0usize];
            if capacity1 < 4usize
            { false }
            else
            {
                out[0usize] = capacity1.wrapping_sub(4usize);
                true
            }
        }
        else if xh1.additional_info == additional_info_long_argument_64_bits
        {
            let capacity1: usize = out[0usize];
            if capacity1 < 8usize
            { false }
            else
            {
                out[0usize] = capacity1.wrapping_sub(8usize);
                true
            }
        }
        else
        { true }
    }
    else
    { false }
}

#[derive(PartialEq, Clone, Copy)]
enum option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_raw <'a>
{
    None,
    Some { v: &'a [cbor_raw <'a>] }
}

#[derive(PartialEq, Clone, Copy)]
enum option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_map_entry <'a>
{
    None,
    Some { v: &'a [cbor_map_entry <'a>] }
}

pub(crate) fn siz·_d(x·: cbor_raw, out: &mut [usize]) -> bool
{
    let deep: bool = compute_deep(x·);
    if deep
    {
        let
        xh1: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            cbor_raw_with_perm_get_header_d(x·);
        let res1: bool = size_header(xh1, out);
        if res1
        {
            let b: initial_byte_t = xh1._1;
            if
            b.major_type == cbor_major_type_byte_string
            ||
            b.major_type == cbor_major_type_text_string
            {
                let x2·: &[u8] =
                    match x·
                    {
                        cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_ptr,
                        _ => panic!("Incomplete pattern matching")
                    };
                let length: usize = x2·.len();
                let cur: usize = out[0usize];
                if cur < length
                { false }
                else
                {
                    out[0usize] = cur.wrapping_sub(length);
                    true
                }
            }
            else
            {
                let b0: initial_byte_t = xh1._1;
                if b0.major_type == cbor_major_type_array
                {
                    if match x· { cbor_raw::CBOR_Case_Array { .. } => true, _ => false }
                    {
                        let a: &[cbor_raw] =
                            match
                            match x·
                            {
                                cbor_raw::CBOR_Case_Array { v: a } =>
                                  option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_raw::Some
                                  { v: a.cbor_array_ptr },
                                _ =>
                                  option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_raw::None
                            }
                            {
                                option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_raw::Some
                                { v: v1 }
                                => v1,
                                _ => panic!("Incomplete pattern matching")
                            };
                        let mut pres: [bool; 1] = [true; 1usize];
                        let mut pi: [usize; 1] = [0usize; 1usize];
                        let len: usize = a.len();
                        while
                        true
                        {
                            let res: bool = (&pres)[0usize];
                            let i: usize = (&pi)[0usize];
                            if ! (res && i < len) { break };
                            let i0: usize = (&pi)[0usize];
                            let e: cbor_raw = a[i0];
                            let res0: bool = siz·_d(e, out);
                            if res0
                            {
                                let i·: usize = i0.wrapping_add(1usize);
                                (&mut pi)[0usize] = i·
                            }
                            else
                            { (&mut pres)[0usize] = false }
                        };
                        (&pres)[0usize]
                    }
                    else
                    {
                        let x2·: &[u8] =
                            match x·
                            {
                                cbor_raw::CBOR_Case_Serialized_Array { v: xs } =>
                                  xs.cbor_serialized_payload,
                                _ => panic!("Incomplete pattern matching")
                            };
                        let length: usize = x2·.len();
                        let cur: usize = out[0usize];
                        if cur < length
                        { false }
                        else
                        {
                            out[0usize] = cur.wrapping_sub(length);
                            true
                        }
                    }
                }
                else
                {
                    let b1: initial_byte_t = xh1._1;
                    if b1.major_type == cbor_major_type_map
                    {
                        if match x· { cbor_raw::CBOR_Case_Map { .. } => true, _ => false }
                        {
                            let a: &[cbor_map_entry] =
                                match
                                match x·
                                {
                                    cbor_raw::CBOR_Case_Map { v: a } =>
                                      option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_map_entry::Some
                                      { v: a.cbor_map_ptr },
                                    _ =>
                                      option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_map_entry::None
                                }
                                {
                                    option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_map_entry::Some
                                    { v: v1 }
                                    => v1,
                                    _ => panic!("Incomplete pattern matching")
                                };
                            let mut pres: [bool; 1] = [true; 1usize];
                            let mut pi: [usize; 1] = [0usize; 1usize];
                            let len: usize = a.len();
                            while
                            true
                            {
                                let res: bool = (&pres)[0usize];
                                let i: usize = (&pi)[0usize];
                                if ! (res && i < len) { break };
                                let i0: usize = (&pi)[0usize];
                                let e: cbor_map_entry = a[i0];
                                let x1: cbor_raw = e.cbor_map_entry_key;
                                let res11: bool = siz·_d(x1, out);
                                let res0: bool =
                                    if res11
                                    {
                                        let x2: cbor_raw = e.cbor_map_entry_value;
                                        siz·_d(x2, out)
                                    }
                                    else
                                    { false };
                                if res0
                                {
                                    let i·: usize = i0.wrapping_add(1usize);
                                    (&mut pi)[0usize] = i·
                                }
                                else
                                { (&mut pres)[0usize] = false }
                            };
                            (&pres)[0usize]
                        }
                        else
                        {
                            let x2·: &[u8] =
                                match x·
                                {
                                    cbor_raw::CBOR_Case_Serialized_Map { v: xs } =>
                                      xs.cbor_serialized_payload,
                                    _ => panic!("Incomplete pattern matching")
                                };
                            let length: usize = x2·.len();
                            let cur: usize = out[0usize];
                            if cur < length
                            { false }
                            else
                            {
                                out[0usize] = cur.wrapping_sub(length);
                                true
                            }
                        }
                    }
                    else
                    {
                        let b2: initial_byte_t = xh1._1;
                        if b2.major_type == cbor_major_type_tagged
                        {
                            if match x· { cbor_raw::CBOR_Case_Tagged { .. } => true, _ => false }
                            {
                                let x2·: cbor_raw =
                                    match x·
                                    {
                                        cbor_raw::CBOR_Case_Tagged { v: tg } =>
                                          tg.cbor_tagged_ptr[0usize],
                                        _ => panic!("Incomplete pattern matching")
                                    };
                                siz·_d(x2·, out)
                            }
                            else
                            {
                                let x2·: &[u8] =
                                    match x·
                                    {
                                        cbor_raw::CBOR_Case_Serialized_Tagged { v: ser } =>
                                          ser.cbor_serialized_payload,
                                        _ => panic!("Incomplete pattern matching")
                                    };
                                let length: usize = x2·.len();
                                let cur: usize = out[0usize];
                                if cur < length
                                { false }
                                else
                                {
                                    out[0usize] = cur.wrapping_sub(length);
                                    true
                                }
                            }
                        }
                        else
                        { true }
                    }
                }
            }
        }
        else
        { false }
    }
    else
    {
        let
        xh1: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            cbor_raw_with_perm_get_header_d(x·);
        let res1: bool = size_header(xh1, out);
        if res1
        {
            let b: initial_byte_t = xh1._1;
            if
            b.major_type == cbor_major_type_byte_string
            ||
            b.major_type == cbor_major_type_text_string
            {
                let x2·: &[u8] =
                    match x·
                    {
                        cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_ptr,
                        _ => panic!("Incomplete pattern matching")
                    };
                let length: usize = x2·.len();
                let cur: usize = out[0usize];
                if cur < length
                { false }
                else
                {
                    out[0usize] = cur.wrapping_sub(length);
                    true
                }
            }
            else
            {
                let b0: initial_byte_t = xh1._1;
                if b0.major_type == cbor_major_type_array
                {
                    if match x· { cbor_raw::CBOR_Case_Array { .. } => true, _ => false }
                    { true }
                    else
                    {
                        let x2·: &[u8] =
                            match x·
                            {
                                cbor_raw::CBOR_Case_Serialized_Array { v: xs } =>
                                  xs.cbor_serialized_payload,
                                _ => panic!("Incomplete pattern matching")
                            };
                        let length: usize = x2·.len();
                        let cur: usize = out[0usize];
                        if cur < length
                        { false }
                        else
                        {
                            out[0usize] = cur.wrapping_sub(length);
                            true
                        }
                    }
                }
                else
                {
                    let b1: initial_byte_t = xh1._1;
                    if b1.major_type == cbor_major_type_map
                    {
                        if match x· { cbor_raw::CBOR_Case_Map { .. } => true, _ => false }
                        { true }
                        else
                        {
                            let x2·: &[u8] =
                                match x·
                                {
                                    cbor_raw::CBOR_Case_Serialized_Map { v: xs } =>
                                      xs.cbor_serialized_payload,
                                    _ => panic!("Incomplete pattern matching")
                                };
                            let length: usize = x2·.len();
                            let cur: usize = out[0usize];
                            if cur < length
                            { false }
                            else
                            {
                                out[0usize] = cur.wrapping_sub(length);
                                true
                            }
                        }
                    }
                    else
                    {
                        let b2: initial_byte_t = xh1._1;
                        if b2.major_type == cbor_major_type_tagged
                        {
                            if match x· { cbor_raw::CBOR_Case_Tagged { .. } => true, _ => false }
                            {
                                match x·
                                {
                                    cbor_raw::CBOR_Case_Tagged { .. } => false,
                                    _ => panic!("Incomplete pattern matching")
                                }
                            }
                            else
                            {
                                let x2·: &[u8] =
                                    match x·
                                    {
                                        cbor_raw::CBOR_Case_Serialized_Tagged { v: ser } =>
                                          ser.cbor_serialized_payload,
                                        _ => panic!("Incomplete pattern matching")
                                    };
                                let length: usize = x2·.len();
                                let cur: usize = out[0usize];
                                if cur < length
                                { false }
                                else
                                {
                                    out[0usize] = cur.wrapping_sub(length);
                                    true
                                }
                            }
                        }
                        else
                        { true }
                    }
                }
            }
        }
        else
        { false }
    }
}

fn cbor_size(x: cbor_raw, bound: usize) -> usize
{
    let mut output: [usize; 1] = [bound; 1usize];
    let res: bool = siz·_d(x, &mut output);
    if res
    {
        let rem: usize = (&output)[0usize];
        bound.wrapping_sub(rem)
    }
    else
    { 0usize }
}

fn dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
    t: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
) ->
    long_argument
{ t._2 }

fn write_header(
    x: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument,
    out: &mut [u8],
    offset: usize
) ->
    usize
{
    let xh1: initial_byte_t =
        dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(x);
    let pos·: usize = offset.wrapping_add(1usize);
    let n·: u8 =
        set_bitfield_gen8(
            set_bitfield_gen8(0u8, 0u32, 5u32, xh1.additional_info),
            5u32,
            8u32,
            xh1.major_type
        );
    out[pos·.wrapping_sub(1usize)] = n·;
    let x2·: long_argument =
        dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(x);
    if xh1.additional_info == additional_info_long_argument_8_bits
    {
        if xh1.major_type == cbor_major_type_simple_value
        {
            let pos·1: usize = pos·.wrapping_add(1usize);
            let n·1: u8 =
                match x2·
                {
                    long_argument::LongArgumentSimpleValue { v } => v,
                    _ => panic!("Incomplete pattern matching")
                };
            out[pos·1.wrapping_sub(1usize)] = n·1;
            pos·1
        }
        else
        {
            let pos·1: usize = pos·.wrapping_add(1usize);
            let n·1: u8 =
                match x2·
                {
                    long_argument::LongArgumentU8 { v } => v,
                    _ => panic!("Incomplete pattern matching")
                };
            out[pos·1.wrapping_sub(1usize)] = n·1;
            pos·1
        }
    }
    else if xh1.additional_info == additional_info_long_argument_16_bits
    {
        let pos·1: usize = pos·.wrapping_add(2usize);
        let lo: u8 =
            match x2·
            {
                long_argument::LongArgumentU16 { v } => v,
                _ => panic!("Incomplete pattern matching")
            }
            as
            u8;
        let hi: u16 =
            match x2·
            {
                long_argument::LongArgumentU16 { v } => v,
                _ => panic!("Incomplete pattern matching")
            }.wrapping_div(256u16);
        let pos·2: usize = pos·1.wrapping_sub(1usize);
        let n·1: u8 = hi as u8;
        out[pos·2.wrapping_sub(1usize)] = n·1;
        out[pos·2] = lo;
        pos·1
    }
    else if xh1.additional_info == additional_info_long_argument_32_bits
    {
        let pos·1: usize = pos·.wrapping_add(4usize);
        let lo: u8 =
            match x2·
            {
                long_argument::LongArgumentU32 { v } => v,
                _ => panic!("Incomplete pattern matching")
            }
            as
            u8;
        let hi: u32 =
            match x2·
            {
                long_argument::LongArgumentU32 { v } => v,
                _ => panic!("Incomplete pattern matching")
            }.wrapping_div(256u32);
        let pos·2: usize = pos·1.wrapping_sub(1usize);
        let lo1: u8 = hi as u8;
        let hi1: u32 = hi.wrapping_div(256u32);
        let pos·3: usize = pos·2.wrapping_sub(1usize);
        let lo2: u8 = hi1 as u8;
        let hi2: u32 = hi1.wrapping_div(256u32);
        let pos·4: usize = pos·3.wrapping_sub(1usize);
        let n·1: u8 = hi2 as u8;
        out[pos·4.wrapping_sub(1usize)] = n·1;
        out[pos·4] = lo2;
        out[pos·3] = lo1;
        out[pos·2] = lo;
        pos·1
    }
    else if xh1.additional_info == additional_info_long_argument_64_bits
    {
        let pos·1: usize = pos·.wrapping_add(8usize);
        let lo: u8 =
            match x2·
            {
                long_argument::LongArgumentU64 { v } => v,
                _ => panic!("Incomplete pattern matching")
            }
            as
            u8;
        let hi: u64 =
            match x2·
            {
                long_argument::LongArgumentU64 { v } => v,
                _ => panic!("Incomplete pattern matching")
            }.wrapping_div(256u64);
        let pos·2: usize = pos·1.wrapping_sub(1usize);
        let lo1: u8 = hi as u8;
        let hi1: u64 = hi.wrapping_div(256u64);
        let pos·3: usize = pos·2.wrapping_sub(1usize);
        let lo2: u8 = hi1 as u8;
        let hi2: u64 = hi1.wrapping_div(256u64);
        let pos·4: usize = pos·3.wrapping_sub(1usize);
        let lo3: u8 = hi2 as u8;
        let hi3: u64 = hi2.wrapping_div(256u64);
        let pos·5: usize = pos·4.wrapping_sub(1usize);
        let lo4: u8 = hi3 as u8;
        let hi4: u64 = hi3.wrapping_div(256u64);
        let pos·6: usize = pos·5.wrapping_sub(1usize);
        let lo5: u8 = hi4 as u8;
        let hi5: u64 = hi4.wrapping_div(256u64);
        let pos·7: usize = pos·6.wrapping_sub(1usize);
        let lo6: u8 = hi5 as u8;
        let hi6: u64 = hi5.wrapping_div(256u64);
        let pos·8: usize = pos·7.wrapping_sub(1usize);
        let n·1: u8 = hi6 as u8;
        out[pos·8.wrapping_sub(1usize)] = n·1;
        out[pos·8] = lo6;
        out[pos·7] = lo5;
        out[pos·6] = lo4;
        out[pos·5] = lo3;
        out[pos·4] = lo2;
        out[pos·3] = lo1;
        out[pos·2] = lo;
        pos·1
    }
    else
    { pos· }
}

pub(crate) fn ser·_d(x·: cbor_raw, out: &mut [u8], offset: usize) -> usize
{
    let deep: bool = compute_deep(x·);
    if deep
    {
        let
        xh1: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            cbor_raw_with_perm_get_header_d(x·);
        let res1: usize = write_header(xh1, out, offset);
        let b: initial_byte_t = xh1._1;
        if
        b.major_type == cbor_major_type_byte_string || b.major_type == cbor_major_type_text_string
        {
            let x2·: &[u8] =
                match x·
                {
                    cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_ptr,
                    _ => panic!("Incomplete pattern matching")
                };
            let length: usize = x2·.len();
            let _letpattern: (&mut [u8], &mut [u8]) = out.split_at_mut(res1);
            let _sp11: &[u8] = _letpattern.0;
            let sp12: &mut [u8] = _letpattern.1;
            let _letpattern1: (&mut [u8], &mut [u8]) = sp12.split_at_mut(length);
            let sp21: &mut [u8] = _letpattern1.0;
            let _sp22: &[u8] = _letpattern1.1;
            sp21.copy_from_slice(x2·);
            res1.wrapping_add(length)
        }
        else
        {
            let b0: initial_byte_t = xh1._1;
            if b0.major_type == cbor_major_type_array
            {
                if match x· { cbor_raw::CBOR_Case_Array { .. } => true, _ => false }
                {
                    let a: &[cbor_raw] =
                        match
                        match x·
                        {
                            cbor_raw::CBOR_Case_Array { v: a } =>
                              option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_raw::Some
                              { v: a.cbor_array_ptr },
                            _ => option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_raw::None
                        }
                        {
                            option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_raw::Some
                            { v: v1 }
                            => v1,
                            _ => panic!("Incomplete pattern matching")
                        };
                    let mut pres: [usize; 1] = [res1; 1usize];
                    let mut pi: [usize; 1] = [0usize; 1usize];
                    let len: usize = a.len();
                    while
                    true
                    {
                        let i: usize = (&pi)[0usize];
                        if i >= len { break };
                        let i0: usize = (&pi)[0usize];
                        let off: usize = (&pres)[0usize];
                        let e: cbor_raw = a[i0];
                        let i·: usize = i0.wrapping_add(1usize);
                        let res: usize = ser·_d(e, out, off);
                        (&mut pi)[0usize] = i·;
                        (&mut pres)[0usize] = res
                    };
                    (&pres)[0usize]
                }
                else
                {
                    let x2·: &[u8] =
                        match x·
                        {
                            cbor_raw::CBOR_Case_Serialized_Array { v: xs } =>
                              xs.cbor_serialized_payload,
                            _ => panic!("Incomplete pattern matching")
                        };
                    let length: usize = x2·.len();
                    let _letpattern: (&mut [u8], &mut [u8]) = out.split_at_mut(res1);
                    let _sp11: &[u8] = _letpattern.0;
                    let sp12: &mut [u8] = _letpattern.1;
                    let _letpattern1: (&mut [u8], &mut [u8]) = sp12.split_at_mut(length);
                    let sp21: &mut [u8] = _letpattern1.0;
                    let _sp22: &[u8] = _letpattern1.1;
                    sp21.copy_from_slice(x2·);
                    res1.wrapping_add(length)
                }
            }
            else
            {
                let b1: initial_byte_t = xh1._1;
                if b1.major_type == cbor_major_type_map
                {
                    if match x· { cbor_raw::CBOR_Case_Map { .. } => true, _ => false }
                    {
                        let a: &[cbor_map_entry] =
                            match
                            match x·
                            {
                                cbor_raw::CBOR_Case_Map { v: a } =>
                                  option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_map_entry::Some
                                  { v: a.cbor_map_ptr },
                                _ =>
                                  option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_map_entry::None
                            }
                            {
                                option__Pulse_Lib_Slice_slice·CBOR_Pulse_Raw_Type_cbor_map_entry::Some
                                { v: v1 }
                                => v1,
                                _ => panic!("Incomplete pattern matching")
                            };
                        let mut pres: [usize; 1] = [res1; 1usize];
                        let mut pi: [usize; 1] = [0usize; 1usize];
                        let len: usize = a.len();
                        while
                        true
                        {
                            let i: usize = (&pi)[0usize];
                            if i >= len { break };
                            let i0: usize = (&pi)[0usize];
                            let off: usize = (&pres)[0usize];
                            let e: cbor_map_entry = a[i0];
                            let i·: usize = i0.wrapping_add(1usize);
                            let x1: cbor_raw = e.cbor_map_entry_key;
                            let res11: usize = ser·_d(x1, out, off);
                            let x2: cbor_raw = e.cbor_map_entry_value;
                            let res: usize = ser·_d(x2, out, res11);
                            (&mut pi)[0usize] = i·;
                            (&mut pres)[0usize] = res
                        };
                        (&pres)[0usize]
                    }
                    else
                    {
                        let x2·: &[u8] =
                            match x·
                            {
                                cbor_raw::CBOR_Case_Serialized_Map { v: xs } =>
                                  xs.cbor_serialized_payload,
                                _ => panic!("Incomplete pattern matching")
                            };
                        let length: usize = x2·.len();
                        let _letpattern: (&mut [u8], &mut [u8]) = out.split_at_mut(res1);
                        let _sp11: &[u8] = _letpattern.0;
                        let sp12: &mut [u8] = _letpattern.1;
                        let _letpattern1: (&mut [u8], &mut [u8]) = sp12.split_at_mut(length);
                        let sp21: &mut [u8] = _letpattern1.0;
                        let _sp22: &[u8] = _letpattern1.1;
                        sp21.copy_from_slice(x2·);
                        res1.wrapping_add(length)
                    }
                }
                else
                {
                    let b2: initial_byte_t = xh1._1;
                    if b2.major_type == cbor_major_type_tagged
                    {
                        if match x· { cbor_raw::CBOR_Case_Tagged { .. } => true, _ => false }
                        {
                            let x2·: cbor_raw =
                                match x·
                                {
                                    cbor_raw::CBOR_Case_Tagged { v: tg } =>
                                      tg.cbor_tagged_ptr[0usize],
                                    _ => panic!("Incomplete pattern matching")
                                };
                            ser·_d(x2·, out, res1)
                        }
                        else
                        {
                            let x2·: &[u8] =
                                match x·
                                {
                                    cbor_raw::CBOR_Case_Serialized_Tagged { v: ser } =>
                                      ser.cbor_serialized_payload,
                                    _ => panic!("Incomplete pattern matching")
                                };
                            let length: usize = x2·.len();
                            let _letpattern: (&mut [u8], &mut [u8]) = out.split_at_mut(res1);
                            let _sp11: &[u8] = _letpattern.0;
                            let sp12: &mut [u8] = _letpattern.1;
                            let _letpattern1: (&mut [u8], &mut [u8]) = sp12.split_at_mut(length);
                            let sp21: &mut [u8] = _letpattern1.0;
                            let _sp22: &[u8] = _letpattern1.1;
                            sp21.copy_from_slice(x2·);
                            res1.wrapping_add(length)
                        }
                    }
                    else
                    { res1 }
                }
            }
        }
    }
    else
    {
        let
        xh1: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            cbor_raw_with_perm_get_header_d(x·);
        let res1: usize = write_header(xh1, out, offset);
        let b: initial_byte_t = xh1._1;
        if
        b.major_type == cbor_major_type_byte_string || b.major_type == cbor_major_type_text_string
        {
            let x2·: &[u8] =
                match x·
                {
                    cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_ptr,
                    _ => panic!("Incomplete pattern matching")
                };
            let length: usize = x2·.len();
            let _letpattern: (&mut [u8], &mut [u8]) = out.split_at_mut(res1);
            let _sp11: &[u8] = _letpattern.0;
            let sp12: &mut [u8] = _letpattern.1;
            let _letpattern1: (&mut [u8], &mut [u8]) = sp12.split_at_mut(length);
            let sp21: &mut [u8] = _letpattern1.0;
            let _sp22: &[u8] = _letpattern1.1;
            sp21.copy_from_slice(x2·);
            res1.wrapping_add(length)
        }
        else
        {
            let b0: initial_byte_t = xh1._1;
            if b0.major_type == cbor_major_type_array
            {
                if match x· { cbor_raw::CBOR_Case_Array { .. } => true, _ => false }
                { res1 }
                else
                {
                    let x2·: &[u8] =
                        match x·
                        {
                            cbor_raw::CBOR_Case_Serialized_Array { v: xs } =>
                              xs.cbor_serialized_payload,
                            _ => panic!("Incomplete pattern matching")
                        };
                    let length: usize = x2·.len();
                    let _letpattern: (&mut [u8], &mut [u8]) = out.split_at_mut(res1);
                    let _sp11: &[u8] = _letpattern.0;
                    let sp12: &mut [u8] = _letpattern.1;
                    let _letpattern1: (&mut [u8], &mut [u8]) = sp12.split_at_mut(length);
                    let sp21: &mut [u8] = _letpattern1.0;
                    let _sp22: &[u8] = _letpattern1.1;
                    sp21.copy_from_slice(x2·);
                    res1.wrapping_add(length)
                }
            }
            else
            {
                let b1: initial_byte_t = xh1._1;
                if b1.major_type == cbor_major_type_map
                {
                    if match x· { cbor_raw::CBOR_Case_Map { .. } => true, _ => false }
                    { res1 }
                    else
                    {
                        let x2·: &[u8] =
                            match x·
                            {
                                cbor_raw::CBOR_Case_Serialized_Map { v: xs } =>
                                  xs.cbor_serialized_payload,
                                _ => panic!("Incomplete pattern matching")
                            };
                        let length: usize = x2·.len();
                        let _letpattern: (&mut [u8], &mut [u8]) = out.split_at_mut(res1);
                        let _sp11: &[u8] = _letpattern.0;
                        let sp12: &mut [u8] = _letpattern.1;
                        let _letpattern1: (&mut [u8], &mut [u8]) = sp12.split_at_mut(length);
                        let sp21: &mut [u8] = _letpattern1.0;
                        let _sp22: &[u8] = _letpattern1.1;
                        sp21.copy_from_slice(x2·);
                        res1.wrapping_add(length)
                    }
                }
                else
                {
                    let b2: initial_byte_t = xh1._1;
                    if b2.major_type == cbor_major_type_tagged
                    {
                        if match x· { cbor_raw::CBOR_Case_Tagged { .. } => true, _ => false }
                        {
                            match x·
                            {
                                cbor_raw::CBOR_Case_Tagged { .. } => res1,
                                _ => panic!("Incomplete pattern matching")
                            }
                        }
                        else
                        {
                            let x2·: &[u8] =
                                match x·
                                {
                                    cbor_raw::CBOR_Case_Serialized_Tagged { v: ser } =>
                                      ser.cbor_serialized_payload,
                                    _ => panic!("Incomplete pattern matching")
                                };
                            let length: usize = x2·.len();
                            let _letpattern: (&mut [u8], &mut [u8]) = out.split_at_mut(res1);
                            let _sp11: &[u8] = _letpattern.0;
                            let sp12: &mut [u8] = _letpattern.1;
                            let _letpattern1: (&mut [u8], &mut [u8]) = sp12.split_at_mut(length);
                            let sp21: &mut [u8] = _letpattern1.0;
                            let _sp22: &[u8] = _letpattern1.1;
                            sp21.copy_from_slice(x2·);
                            res1.wrapping_add(length)
                        }
                    }
                    else
                    { res1 }
                }
            }
        }
    }
}

fn cbor_serialize(x: cbor_raw, output: &mut [u8]) -> usize { ser·_d(x, output, 0usize) }

fn impl_uint8_compare(x1: u8, x2: u8) -> i16
{ if x1 < x2 { -1i16 } else if x1 > x2 { 1i16 } else { 0i16 } }

fn lex_compare_bytes(s1: &[u8], s2: &[u8]) -> i16
{
    let mut pi1: [usize; 1] = [0usize; 1usize];
    let mut pi2: [usize; 1] = [0usize; 1usize];
    let n1: usize = s1.len();
    let n2: usize = s2.len();
    let mut pres: [i16; 1] =
        [if 0usize < n1
            { if 0usize < n2 { 0i16 } else { 1i16 } }
            else if 0usize < n2 { -1i16 } else { 0i16 };
            1usize];
    while
    true
    {
        let res: i16 = (&pres)[0usize];
        let i1: usize = (&pi1)[0usize];
        if ! (res == 0i16 && i1 < n1) { break };
        let i10: usize = (&pi1)[0usize];
        let x1: u8 = s1[i10];
        let i2: usize = (&pi2)[0usize];
        let x2: u8 = s2[i2];
        let c: i16 = impl_uint8_compare(x1, x2);
        if c == 0i16
        {
            let i1·: usize = i10.wrapping_add(1usize);
            let i2·: usize = i2.wrapping_add(1usize);
            let ci1·: bool = i1· < n1;
            let ci2·: bool = i2· < n2;
            if ci2· && ! ci1·
            { (&mut pres)[0usize] = -1i16 }
            else if ci1· && ! ci2·
            { (&mut pres)[0usize] = 1i16 }
            else
            {
                (&mut pi1)[0usize] = i1·;
                (&mut pi2)[0usize] = i2·
            }
        }
        else
        { (&mut pres)[0usize] = c }
    };
    (&pres)[0usize]
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum option__bool
{
    None,
    Some { v: bool }
}

fn eq_Some_true(x: option__bool) -> bool
{ match x { option__bool::Some { v: b } => b, _ => false } }

fn eq_Some_false(x: option__bool) -> bool
{ match x { option__bool::Some { v: b } => ! b, _ => false } }

fn eq_Some_0sz(x: option__size_t) -> bool
{ match x { option__size_t::Some { v: y } => y == 0usize, _ => false } }

pub(crate) fn impl_check_map_depth_aux(bound: usize, pl: &mut [&[u8]], n1: usize) -> bool
{
    let mut pn: [usize; 1] = [n1; 1usize];
    let mut pres: [bool; 1] = [true; 1usize];
    while
    true
    {
        let res: bool = (&pres)[0usize];
        let n: usize = (&pn)[0usize];
        if ! (res && n > 0usize) { break };
        let l: &[u8] = pl[0usize];
        let n0: usize = (&pn)[0usize];
        let n·: usize = n0.wrapping_sub(1usize);
        let i: usize = jump_header(l, 0usize);
        let _letpattern: (&[u8], &[u8]) = l.split_at(i);
        let hd: &[u8] = _letpattern.0;
        let tl·: &[u8] = _letpattern.1;
        let
        h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            read_header(hd);
        let b: initial_byte_t = h._1;
        let i1: usize =
            if
            b.major_type == cbor_major_type_byte_string
            ||
            b.major_type == cbor_major_type_text_string
            { argument_as_uint64(h._1, h._2) as usize }
            else
            { 0usize };
        let _letpattern1: (&[u8], &[u8]) = tl·.split_at(i1);
        let tl: &[u8] = _letpattern1.1;
        let m: u8 = get_header_major_type(h);
        if m == cbor_major_type_tagged
        { pl[0usize] = tl }
        else if m == cbor_major_type_array
        {
            pl[0usize] = tl;
            (&mut pn)[0usize] = (impl_remaining_data_items_header(h)).wrapping_add(n·)
        }
        else if m == cbor_major_type_map
        {
            if bound == 0usize
            { (&mut pres)[0usize] = false }
            else
            {
                pl[0usize] = tl;
                let res0: bool =
                    impl_check_map_depth_aux(
                        bound.wrapping_sub(1usize),
                        pl,
                        impl_remaining_data_items_header(h)
                    );
                if res0 { (&mut pn)[0usize] = n· } else { (&mut pres)[0usize] = false }
            }
        }
        else
        {
            pl[0usize] = tl;
            (&mut pn)[0usize] = n·
        }
    };
    (&pres)[0usize]
}

fn impl_check_map_depth(bound: usize, n0: usize, l0: &[u8]) -> bool
{
    let mut pl: [&[u8]; 1] = [l0; 1usize];
    impl_check_map_depth_aux(bound, &mut pl, n0)
}

fn impl_check_map_depth_opt(bound: option__size_t, n0: usize, l0: &[u8]) -> bool
{
    if match bound { option__size_t::None => true, _ => false }
    { true }
    else
    {
        impl_check_map_depth(
            match bound
            { option__size_t::Some { v } => v, _ => panic!("Incomplete pattern matching") },
            n0,
            l0
        )
    }
}

pub(crate) fn impl_check_equiv_map_hd_basic(map_bound: option__size_t, l1: &[u8], l2: &[u8]) ->
    option__bool
{
    let i: usize = jump_header(l1, 0usize);
    let _letpattern: (&[u8], &[u8]) = l1.split_at(i);
    let ph1: &[u8] =
        {
            let input1: &[u8] = _letpattern.0;
            let _input2: &[u8] = _letpattern.1;
            input1
        };
    let h1: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument =
        read_header(ph1);
    let i1: usize = jump_header(l2, 0usize);
    let _letpattern1: (&[u8], &[u8]) = l2.split_at(i1);
    let ph2: &[u8] =
        {
            let input1: &[u8] = _letpattern1.0;
            let _input2: &[u8] = _letpattern1.1;
            input1
        };
    let h2: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument =
        read_header(ph2);
    let mt1: u8 = get_header_major_type(h1);
    let mt2: u8 = get_header_major_type(h2);
    if mt1 == cbor_major_type_map && mt2 == cbor_major_type_map
    {
        if eq_Some_0sz(map_bound)
        { option__bool::None }
        else
        {
            let map_bound·: option__size_t =
                match map_bound
                {
                    option__size_t::None => option__size_t::None,
                    option__size_t::Some { v: b } =>
                      option__size_t::Some { v: b.wrapping_sub(1usize) },
                    _ => panic!("Incomplete pattern matching")
                };
            let i2: usize = jump_raw_data_item(l1, 0usize);
            let _letpattern2: (&[u8], &[u8]) = l1.split_at(i2);
            let map1: &[u8] =
                {
                    let input1: &[u8] = _letpattern2.0;
                    let _input2: &[u8] = _letpattern2.1;
                    input1
                };
            let
            mut
            ph:
            [dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument;
            1]
            =
                [h1; 1usize];
            let i3: usize = jump_header(map1, 0usize);
            let _letpattern3: (&[u8], &[u8]) = map1.split_at(i3);
            let c1: &[u8] =
                {
                    let ph3: &[u8] = _letpattern3.0;
                    let outc: &[u8] = _letpattern3.1;
                    let
                    h:
                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                    =
                        read_header(ph3);
                    (&mut ph)[0usize] = h;
                    outc
                };
            let nv1: usize =
                argument_as_uint64(
                    dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                        h1
                    ),
                    dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                        h1
                    )
                )
                as
                usize;
            let i4: usize = jump_raw_data_item(l2, 0usize);
            let _letpattern4: (&[u8], &[u8]) = l2.split_at(i4);
            let map2: &[u8] =
                {
                    let input1: &[u8] = _letpattern4.0;
                    let _input2: &[u8] = _letpattern4.1;
                    input1
                };
            let i5: usize = jump_header(map2, 0usize);
            let _letpattern5: (&[u8], &[u8]) = map2.split_at(i5);
            let c2: &[u8] =
                {
                    let ph3: &[u8] = _letpattern5.0;
                    let outc: &[u8] = _letpattern5.1;
                    let
                    h:
                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                    =
                        read_header(ph3);
                    (&mut ph)[0usize] = h;
                    outc
                };
            let nv2: usize =
                argument_as_uint64(
                    dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                        h2
                    ),
                    dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                        h2
                    )
                )
                as
                usize;
            let mut pl: [&[u8]; 1] = [c1; 1usize];
            let mut pn: [usize; 1] = [nv1; 1usize];
            let mut pres: [option__bool; 1] = [option__bool::Some { v: true }; 1usize];
            while
            true
            {
                let n: usize = (&pn)[0usize];
                let res: option__bool = (&pres)[0usize];
                if ! (n > 0usize && eq_Some_true(res)) { break };
                let l: &[u8] = (&pl)[0usize];
                let n0: usize = (&pn)[0usize];
                let n·: usize = n0.wrapping_sub(1usize);
                let i6: usize = jump_raw_data_item(l, 0usize);
                let _letpattern6: (&[u8], &[u8]) = l.split_at(i6);
                let lh: &[u8] = _letpattern6.0;
                let lt: &[u8] = _letpattern6.1;
                let i7: usize = jump_raw_data_item(lt, 0usize);
                let _letpattern7: (&[u8], &[u8]) = lt.split_at(i7);
                let lv: &[u8] = _letpattern7.0;
                let lt·: &[u8] = _letpattern7.1;
                let mut pll: [&[u8]; 1] = [c2; 1usize];
                let mut pn1: [usize; 1] = [nv2; 1usize];
                let mut pres1: [option__bool; 1] = [option__bool::Some { v: false }; 1usize];
                let mut pcont: [bool; 1] = [true; 1usize];
                while
                true
                {
                    let n1: usize = (&pn1)[0usize];
                    let res0: option__bool = (&pres1)[0usize];
                    let cont: bool = (&pcont)[0usize];
                    if ! (n1 > 0usize && eq_Some_false(res0) && cont) { break };
                    let l3: &[u8] = (&pll)[0usize];
                    let n10: usize = (&pn1)[0usize];
                    let n·1: usize = n10.wrapping_sub(1usize);
                    let i8: usize = jump_raw_data_item(l3, 0usize);
                    let _letpattern8: (&[u8], &[u8]) = l3.split_at(i8);
                    let lh1: &[u8] = _letpattern8.0;
                    let lt1: &[u8] = _letpattern8.1;
                    let mut pn2: [usize; 1] = [1usize; 1usize];
                    let mut pl1: [&[u8]; 1] = [lh; 1usize];
                    let mut pl2: [&[u8]; 1] = [lh1; 1usize];
                    let mut pres2: [option__bool; 1] = [option__bool::Some { v: true }; 1usize];
                    while
                    true
                    {
                        let res1: option__bool = (&pres2)[0usize];
                        let n2: usize = (&pn2)[0usize];
                        if ! (eq_Some_true(res1) && n2 > 0usize) { break };
                        let l1·: &[u8] = (&pl1)[0usize];
                        let l2·: &[u8] = (&pl2)[0usize];
                        let r: option__bool =
                            impl_check_equiv_map_hd_basic(map_bound·, l1·, l2·);
                        if match r { option__bool::None => true, _ => false }
                        { (&mut pres2)[0usize] = r }
                        else
                        {
                            let n20: usize = (&pn2)[0usize];
                            if eq_Some_true(r)
                            {
                                let n·2: usize = n20.wrapping_sub(1usize);
                                let i9: usize = jump_raw_data_item(l1·, 0usize);
                                let _letpattern9: (&[u8], &[u8]) = l1·.split_at(i9);
                                let tl1: &[u8] =
                                    {
                                        let _input1: &[u8] = _letpattern9.0;
                                        let input2: &[u8] = _letpattern9.1;
                                        input2
                                    };
                                let i10: usize = jump_raw_data_item(l2·, 0usize);
                                let _letpattern10: (&[u8], &[u8]) = l2·.split_at(i10);
                                let tl2: &[u8] =
                                    {
                                        let _input1: &[u8] = _letpattern10.0;
                                        let input2: &[u8] = _letpattern10.1;
                                        input2
                                    };
                                (&mut pn2)[0usize] = n·2;
                                (&mut pl1)[0usize] = tl1;
                                (&mut pl2)[0usize] = tl2
                            }
                            else
                            {
                                let i9: usize = jump_header(l1·, 0usize);
                                let _letpattern9: (&[u8], &[u8]) = l1·.split_at(i9);
                                let hd1: &[u8] = _letpattern9.0;
                                let tl1: &[u8] = _letpattern9.1;
                                let
                                h11:
                                dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                                =
                                    read_header(hd1);
                                let mt11: u8 = get_header_major_type(h11);
                                let i10: usize = jump_header(l2·, 0usize);
                                let _letpattern10: (&[u8], &[u8]) = l2·.split_at(i10);
                                let hd2: &[u8] = _letpattern10.0;
                                let tl2: &[u8] = _letpattern10.1;
                                let
                                h21:
                                dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                                =
                                    read_header(hd2);
                                let mt21: u8 = get_header_major_type(h21);
                                if mt11 != mt21
                                { (&mut pres2)[0usize] = option__bool::Some { v: false } }
                                else
                                {
                                    let b: initial_byte_t = h11._1;
                                    let i11: usize =
                                        if
                                        b.major_type == cbor_major_type_byte_string
                                        ||
                                        b.major_type == cbor_major_type_text_string
                                        { argument_as_uint64(h11._1, h11._2) as usize }
                                        else
                                        { 0usize };
                                    let _letpattern11: (&[u8], &[u8]) = tl1.split_at(i11);
                                    let lc1: &[u8] = _letpattern11.0;
                                    let tl1·: &[u8] = _letpattern11.1;
                                    let n·2: usize =
                                        (impl_remaining_data_items_header(h11)).wrapping_add(
                                            n20.wrapping_sub(1usize)
                                        );
                                    let b0: initial_byte_t = h21._1;
                                    let i12: usize =
                                        if
                                        b0.major_type == cbor_major_type_byte_string
                                        ||
                                        b0.major_type == cbor_major_type_text_string
                                        { argument_as_uint64(h21._1, h21._2) as usize }
                                        else
                                        { 0usize };
                                    let _letpattern12: (&[u8], &[u8]) = tl2.split_at(i12);
                                    let lc2: &[u8] = _letpattern12.0;
                                    let tl2·: &[u8] = _letpattern12.1;
                                    let mt12: u8 = get_header_major_type(h11);
                                    let __anf0: bool =
                                        if mt12 == cbor_major_type_simple_value
                                        {
                                            let sv1: u8 =
                                                match
                                                dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                    h11
                                                )
                                                {
                                                    long_argument::LongArgumentOther =>
                                                      (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                          h11
                                                      )).additional_info,
                                                    long_argument::LongArgumentSimpleValue { v } =>
                                                      v,
                                                    _ => panic!("Incomplete pattern matching")
                                                };
                                            let sv2: u8 =
                                                match
                                                dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                    h21
                                                )
                                                {
                                                    long_argument::LongArgumentOther =>
                                                      (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                          h21
                                                      )).additional_info,
                                                    long_argument::LongArgumentSimpleValue { v } =>
                                                      v,
                                                    _ => panic!("Incomplete pattern matching")
                                                };
                                            sv1 == sv2
                                        }
                                        else
                                        {
                                            let len: u64 =
                                                argument_as_uint64(
                                                    dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                        h11
                                                    ),
                                                    dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                        h11
                                                    )
                                                );
                                            let len2: u64 =
                                                argument_as_uint64(
                                                    dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                        h21
                                                    ),
                                                    dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                        h21
                                                    )
                                                );
                                            if len != len2
                                            { false }
                                            else if
                                            mt12 == cbor_major_type_byte_string
                                            ||
                                            mt12 == cbor_major_type_text_string
                                            {
                                                let cmp: i16 = lex_compare_bytes(lc1, lc2);
                                                cmp == 0i16
                                            }
                                            else
                                            { mt12 != cbor_major_type_map }
                                        };
                                    if __anf0
                                    {
                                        (&mut pn2)[0usize] = n·2;
                                        (&mut pl1)[0usize] = tl1·;
                                        (&mut pl2)[0usize] = tl2·
                                    }
                                    else
                                    { (&mut pres2)[0usize] = option__bool::Some { v: false } }
                                }
                            }
                        }
                    };
                    let res1: option__bool = (&pres2)[0usize];
                    if match res1 { option__bool::None => true, _ => false }
                    { (&mut pres1)[0usize] = res1 }
                    else
                    {
                        let i9: usize = jump_raw_data_item(lt1, 0usize);
                        let _letpattern9: (&[u8], &[u8]) = lt1.split_at(i9);
                        let lv1: &[u8] = _letpattern9.0;
                        let lt·1: &[u8] = _letpattern9.1;
                        if
                        match res1
                        {
                            option__bool::Some { v } => v,
                            _ => panic!("Incomplete pattern matching")
                        }
                        {
                            let mut pn3: [usize; 1] = [1usize; 1usize];
                            let mut pl11: [&[u8]; 1] = [lv; 1usize];
                            let mut pl21: [&[u8]; 1] = [lv1; 1usize];
                            let mut pres3: [option__bool; 1] =
                                [option__bool::Some { v: true }; 1usize];
                            while
                            true
                            {
                                let res10: option__bool = (&pres3)[0usize];
                                let n2: usize = (&pn3)[0usize];
                                if ! (eq_Some_true(res10) && n2 > 0usize) { break };
                                let l1·: &[u8] = (&pl11)[0usize];
                                let l2·: &[u8] = (&pl21)[0usize];
                                let r: option__bool =
                                    impl_check_equiv_map_hd_basic(map_bound·, l1·, l2·);
                                if match r { option__bool::None => true, _ => false }
                                { (&mut pres3)[0usize] = r }
                                else
                                {
                                    let n20: usize = (&pn3)[0usize];
                                    if eq_Some_true(r)
                                    {
                                        let n·2: usize = n20.wrapping_sub(1usize);
                                        let i10: usize = jump_raw_data_item(l1·, 0usize);
                                        let _letpattern10: (&[u8], &[u8]) = l1·.split_at(i10);
                                        let tl1: &[u8] =
                                            {
                                                let _input1: &[u8] = _letpattern10.0;
                                                let input2: &[u8] = _letpattern10.1;
                                                input2
                                            };
                                        let i11: usize = jump_raw_data_item(l2·, 0usize);
                                        let _letpattern11: (&[u8], &[u8]) = l2·.split_at(i11);
                                        let tl2: &[u8] =
                                            {
                                                let _input1: &[u8] = _letpattern11.0;
                                                let input2: &[u8] = _letpattern11.1;
                                                input2
                                            };
                                        (&mut pn3)[0usize] = n·2;
                                        (&mut pl11)[0usize] = tl1;
                                        (&mut pl21)[0usize] = tl2
                                    }
                                    else
                                    {
                                        let i10: usize = jump_header(l1·, 0usize);
                                        let _letpattern10: (&[u8], &[u8]) = l1·.split_at(i10);
                                        let hd1: &[u8] = _letpattern10.0;
                                        let tl1: &[u8] = _letpattern10.1;
                                        let
                                        h11:
                                        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                                        =
                                            read_header(hd1);
                                        let mt11: u8 = get_header_major_type(h11);
                                        let i11: usize = jump_header(l2·, 0usize);
                                        let _letpattern11: (&[u8], &[u8]) = l2·.split_at(i11);
                                        let hd2: &[u8] = _letpattern11.0;
                                        let tl2: &[u8] = _letpattern11.1;
                                        let
                                        h21:
                                        dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                                        =
                                            read_header(hd2);
                                        let mt21: u8 = get_header_major_type(h21);
                                        if mt11 != mt21
                                        { (&mut pres3)[0usize] = option__bool::Some { v: false } }
                                        else
                                        {
                                            let b: initial_byte_t = h11._1;
                                            let i12: usize =
                                                if
                                                b.major_type == cbor_major_type_byte_string
                                                ||
                                                b.major_type == cbor_major_type_text_string
                                                { argument_as_uint64(h11._1, h11._2) as usize }
                                                else
                                                { 0usize };
                                            let _letpattern12: (&[u8], &[u8]) = tl1.split_at(i12);
                                            let lc1: &[u8] = _letpattern12.0;
                                            let tl1·: &[u8] = _letpattern12.1;
                                            let n·2: usize =
                                                (impl_remaining_data_items_header(h11)).wrapping_add(
                                                    n20.wrapping_sub(1usize)
                                                );
                                            let b0: initial_byte_t = h21._1;
                                            let i13: usize =
                                                if
                                                b0.major_type == cbor_major_type_byte_string
                                                ||
                                                b0.major_type == cbor_major_type_text_string
                                                { argument_as_uint64(h21._1, h21._2) as usize }
                                                else
                                                { 0usize };
                                            let _letpattern13: (&[u8], &[u8]) = tl2.split_at(i13);
                                            let lc2: &[u8] = _letpattern13.0;
                                            let tl2·: &[u8] = _letpattern13.1;
                                            let mt12: u8 = get_header_major_type(h11);
                                            let __anf0: bool =
                                                if mt12 == cbor_major_type_simple_value
                                                {
                                                    let sv1: u8 =
                                                        match
                                                        dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                            h11
                                                        )
                                                        {
                                                            long_argument::LongArgumentOther =>
                                                              (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                  h11
                                                              )).additional_info,
                                                            long_argument::LongArgumentSimpleValue
                                                            { v }
                                                            => v,
                                                            _ =>
                                                              panic!("Incomplete pattern matching")
                                                        };
                                                    let sv2: u8 =
                                                        match
                                                        dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                            h21
                                                        )
                                                        {
                                                            long_argument::LongArgumentOther =>
                                                              (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                  h21
                                                              )).additional_info,
                                                            long_argument::LongArgumentSimpleValue
                                                            { v }
                                                            => v,
                                                            _ =>
                                                              panic!("Incomplete pattern matching")
                                                        };
                                                    sv1 == sv2
                                                }
                                                else
                                                {
                                                    let len: u64 =
                                                        argument_as_uint64(
                                                            dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                h11
                                                            ),
                                                            dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                h11
                                                            )
                                                        );
                                                    let len2: u64 =
                                                        argument_as_uint64(
                                                            dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                h21
                                                            ),
                                                            dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                h21
                                                            )
                                                        );
                                                    if len != len2
                                                    { false }
                                                    else if
                                                    mt12 == cbor_major_type_byte_string
                                                    ||
                                                    mt12 == cbor_major_type_text_string
                                                    {
                                                        let cmp: i16 = lex_compare_bytes(lc1, lc2);
                                                        cmp == 0i16
                                                    }
                                                    else
                                                    { mt12 != cbor_major_type_map }
                                                };
                                            if __anf0
                                            {
                                                (&mut pn3)[0usize] = n·2;
                                                (&mut pl11)[0usize] = tl1·;
                                                (&mut pl21)[0usize] = tl2·
                                            }
                                            else
                                            {
                                                (&mut pres3)[0usize] =
                                                    option__bool::Some { v: false }
                                            }
                                        }
                                    }
                                }
                            };
                            let __anf0: option__bool = (&pres3)[0usize];
                            (&mut pres1)[0usize] = __anf0;
                            (&mut pcont)[0usize] = false
                        }
                        else
                        {
                            (&mut pll)[0usize] = lt·1;
                            (&mut pn1)[0usize] = n·1
                        }
                    }
                };
                let res0: option__bool = (&pres1)[0usize];
                if eq_Some_true(res0)
                {
                    (&mut pl)[0usize] = lt·;
                    (&mut pn)[0usize] = n·
                }
                else
                { (&mut pres)[0usize] = res0 }
            };
            let res: option__bool = (&pres)[0usize];
            if eq_Some_true(res)
            {
                let mut pl1: [&[u8]; 1] = [c2; 1usize];
                let mut pn1: [usize; 1] = [nv2; 1usize];
                let mut pres1: [option__bool; 1] = [option__bool::Some { v: true }; 1usize];
                while
                true
                {
                    let n: usize = (&pn1)[0usize];
                    let res1: option__bool = (&pres1)[0usize];
                    if ! (n > 0usize && eq_Some_true(res1)) { break };
                    let l: &[u8] = (&pl1)[0usize];
                    let n0: usize = (&pn1)[0usize];
                    let n·: usize = n0.wrapping_sub(1usize);
                    let i6: usize = jump_raw_data_item(l, 0usize);
                    let _letpattern6: (&[u8], &[u8]) = l.split_at(i6);
                    let lh: &[u8] = _letpattern6.0;
                    let lt: &[u8] = _letpattern6.1;
                    let i7: usize = jump_raw_data_item(lt, 0usize);
                    let _letpattern7: (&[u8], &[u8]) = lt.split_at(i7);
                    let lv: &[u8] = _letpattern7.0;
                    let lt·: &[u8] = _letpattern7.1;
                    let mut pll: [&[u8]; 1] = [c1; 1usize];
                    let mut pn2: [usize; 1] = [nv1; 1usize];
                    let mut pres2: [option__bool; 1] = [option__bool::Some { v: false }; 1usize];
                    let mut pcont: [bool; 1] = [true; 1usize];
                    while
                    true
                    {
                        let n1: usize = (&pn2)[0usize];
                        let res10: option__bool = (&pres2)[0usize];
                        let cont: bool = (&pcont)[0usize];
                        if ! (n1 > 0usize && eq_Some_false(res10) && cont) { break };
                        let l3: &[u8] = (&pll)[0usize];
                        let n10: usize = (&pn2)[0usize];
                        let n·1: usize = n10.wrapping_sub(1usize);
                        let i8: usize = jump_raw_data_item(l3, 0usize);
                        let _letpattern8: (&[u8], &[u8]) = l3.split_at(i8);
                        let lh1: &[u8] = _letpattern8.0;
                        let lt1: &[u8] = _letpattern8.1;
                        let mut pn3: [usize; 1] = [1usize; 1usize];
                        let mut pl11: [&[u8]; 1] = [lh; 1usize];
                        let mut pl2: [&[u8]; 1] = [lh1; 1usize];
                        let mut pres3: [option__bool; 1] = [option__bool::Some { v: true }; 1usize];
                        while
                        true
                        {
                            let res11: option__bool = (&pres3)[0usize];
                            let n2: usize = (&pn3)[0usize];
                            if ! (eq_Some_true(res11) && n2 > 0usize) { break };
                            let l1·: &[u8] = (&pl11)[0usize];
                            let l2·: &[u8] = (&pl2)[0usize];
                            let r: option__bool =
                                impl_check_equiv_map_hd_basic(map_bound·, l1·, l2·);
                            if match r { option__bool::None => true, _ => false }
                            { (&mut pres3)[0usize] = r }
                            else
                            {
                                let n20: usize = (&pn3)[0usize];
                                if eq_Some_true(r)
                                {
                                    let n·2: usize = n20.wrapping_sub(1usize);
                                    let i9: usize = jump_raw_data_item(l1·, 0usize);
                                    let _letpattern9: (&[u8], &[u8]) = l1·.split_at(i9);
                                    let tl1: &[u8] =
                                        {
                                            let _input1: &[u8] = _letpattern9.0;
                                            let input2: &[u8] = _letpattern9.1;
                                            input2
                                        };
                                    let i10: usize = jump_raw_data_item(l2·, 0usize);
                                    let _letpattern10: (&[u8], &[u8]) = l2·.split_at(i10);
                                    let tl2: &[u8] =
                                        {
                                            let _input1: &[u8] = _letpattern10.0;
                                            let input2: &[u8] = _letpattern10.1;
                                            input2
                                        };
                                    (&mut pn3)[0usize] = n·2;
                                    (&mut pl11)[0usize] = tl1;
                                    (&mut pl2)[0usize] = tl2
                                }
                                else
                                {
                                    let i9: usize = jump_header(l1·, 0usize);
                                    let _letpattern9: (&[u8], &[u8]) = l1·.split_at(i9);
                                    let hd1: &[u8] = _letpattern9.0;
                                    let tl1: &[u8] = _letpattern9.1;
                                    let
                                    h11:
                                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                                    =
                                        read_header(hd1);
                                    let mt11: u8 = get_header_major_type(h11);
                                    let i10: usize = jump_header(l2·, 0usize);
                                    let _letpattern10: (&[u8], &[u8]) = l2·.split_at(i10);
                                    let hd2: &[u8] = _letpattern10.0;
                                    let tl2: &[u8] = _letpattern10.1;
                                    let
                                    h21:
                                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                                    =
                                        read_header(hd2);
                                    let mt21: u8 = get_header_major_type(h21);
                                    if mt11 != mt21
                                    { (&mut pres3)[0usize] = option__bool::Some { v: false } }
                                    else
                                    {
                                        let b: initial_byte_t = h11._1;
                                        let i11: usize =
                                            if
                                            b.major_type == cbor_major_type_byte_string
                                            ||
                                            b.major_type == cbor_major_type_text_string
                                            { argument_as_uint64(h11._1, h11._2) as usize }
                                            else
                                            { 0usize };
                                        let _letpattern11: (&[u8], &[u8]) = tl1.split_at(i11);
                                        let lc1: &[u8] = _letpattern11.0;
                                        let tl1·: &[u8] = _letpattern11.1;
                                        let n·2: usize =
                                            (impl_remaining_data_items_header(h11)).wrapping_add(
                                                n20.wrapping_sub(1usize)
                                            );
                                        let b0: initial_byte_t = h21._1;
                                        let i12: usize =
                                            if
                                            b0.major_type == cbor_major_type_byte_string
                                            ||
                                            b0.major_type == cbor_major_type_text_string
                                            { argument_as_uint64(h21._1, h21._2) as usize }
                                            else
                                            { 0usize };
                                        let _letpattern12: (&[u8], &[u8]) = tl2.split_at(i12);
                                        let lc2: &[u8] = _letpattern12.0;
                                        let tl2·: &[u8] = _letpattern12.1;
                                        let mt12: u8 = get_header_major_type(h11);
                                        let __anf0: bool =
                                            if mt12 == cbor_major_type_simple_value
                                            {
                                                let sv1: u8 =
                                                    match
                                                    dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                        h11
                                                    )
                                                    {
                                                        long_argument::LongArgumentOther =>
                                                          (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                              h11
                                                          )).additional_info,
                                                        long_argument::LongArgumentSimpleValue
                                                        { v }
                                                        => v,
                                                        _ => panic!("Incomplete pattern matching")
                                                    };
                                                let sv2: u8 =
                                                    match
                                                    dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                        h21
                                                    )
                                                    {
                                                        long_argument::LongArgumentOther =>
                                                          (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                              h21
                                                          )).additional_info,
                                                        long_argument::LongArgumentSimpleValue
                                                        { v }
                                                        => v,
                                                        _ => panic!("Incomplete pattern matching")
                                                    };
                                                sv1 == sv2
                                            }
                                            else
                                            {
                                                let len: u64 =
                                                    argument_as_uint64(
                                                        dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                            h11
                                                        ),
                                                        dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                            h11
                                                        )
                                                    );
                                                let len2: u64 =
                                                    argument_as_uint64(
                                                        dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                            h21
                                                        ),
                                                        dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                            h21
                                                        )
                                                    );
                                                if len != len2
                                                { false }
                                                else if
                                                mt12 == cbor_major_type_byte_string
                                                ||
                                                mt12 == cbor_major_type_text_string
                                                {
                                                    let cmp: i16 = lex_compare_bytes(lc1, lc2);
                                                    cmp == 0i16
                                                }
                                                else
                                                { mt12 != cbor_major_type_map }
                                            };
                                        if __anf0
                                        {
                                            (&mut pn3)[0usize] = n·2;
                                            (&mut pl11)[0usize] = tl1·;
                                            (&mut pl2)[0usize] = tl2·
                                        }
                                        else
                                        { (&mut pres3)[0usize] = option__bool::Some { v: false } }
                                    }
                                }
                            }
                        };
                        let res11: option__bool = (&pres3)[0usize];
                        if match res11 { option__bool::None => true, _ => false }
                        { (&mut pres2)[0usize] = res11 }
                        else
                        {
                            let i9: usize = jump_raw_data_item(lt1, 0usize);
                            let _letpattern9: (&[u8], &[u8]) = lt1.split_at(i9);
                            let lv1: &[u8] = _letpattern9.0;
                            let lt·1: &[u8] = _letpattern9.1;
                            if
                            match res11
                            {
                                option__bool::Some { v } => v,
                                _ => panic!("Incomplete pattern matching")
                            }
                            {
                                let mut pn4: [usize; 1] = [1usize; 1usize];
                                let mut pl12: [&[u8]; 1] = [lv; 1usize];
                                let mut pl21: [&[u8]; 1] = [lv1; 1usize];
                                let mut pres4: [option__bool; 1] =
                                    [option__bool::Some { v: true }; 1usize];
                                while
                                true
                                {
                                    let res2: option__bool = (&pres4)[0usize];
                                    let n2: usize = (&pn4)[0usize];
                                    if ! (eq_Some_true(res2) && n2 > 0usize) { break };
                                    let l1·: &[u8] = (&pl12)[0usize];
                                    let l2·: &[u8] = (&pl21)[0usize];
                                    let r: option__bool =
                                        impl_check_equiv_map_hd_basic(map_bound·, l1·, l2·);
                                    if match r { option__bool::None => true, _ => false }
                                    { (&mut pres4)[0usize] = r }
                                    else
                                    {
                                        let n20: usize = (&pn4)[0usize];
                                        if eq_Some_true(r)
                                        {
                                            let n·2: usize = n20.wrapping_sub(1usize);
                                            let i10: usize = jump_raw_data_item(l1·, 0usize);
                                            let _letpattern10: (&[u8], &[u8]) = l1·.split_at(i10);
                                            let tl1: &[u8] =
                                                {
                                                    let _input1: &[u8] = _letpattern10.0;
                                                    let input2: &[u8] = _letpattern10.1;
                                                    input2
                                                };
                                            let i11: usize = jump_raw_data_item(l2·, 0usize);
                                            let _letpattern11: (&[u8], &[u8]) = l2·.split_at(i11);
                                            let tl2: &[u8] =
                                                {
                                                    let _input1: &[u8] = _letpattern11.0;
                                                    let input2: &[u8] = _letpattern11.1;
                                                    input2
                                                };
                                            (&mut pn4)[0usize] = n·2;
                                            (&mut pl12)[0usize] = tl1;
                                            (&mut pl21)[0usize] = tl2
                                        }
                                        else
                                        {
                                            let i10: usize = jump_header(l1·, 0usize);
                                            let _letpattern10: (&[u8], &[u8]) = l1·.split_at(i10);
                                            let hd1: &[u8] = _letpattern10.0;
                                            let tl1: &[u8] = _letpattern10.1;
                                            let
                                            h11:
                                            dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                                            =
                                                read_header(hd1);
                                            let mt11: u8 = get_header_major_type(h11);
                                            let i11: usize = jump_header(l2·, 0usize);
                                            let _letpattern11: (&[u8], &[u8]) = l2·.split_at(i11);
                                            let hd2: &[u8] = _letpattern11.0;
                                            let tl2: &[u8] = _letpattern11.1;
                                            let
                                            h21:
                                            dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                                            =
                                                read_header(hd2);
                                            let mt21: u8 = get_header_major_type(h21);
                                            if mt11 != mt21
                                            {
                                                (&mut pres4)[0usize] =
                                                    option__bool::Some { v: false }
                                            }
                                            else
                                            {
                                                let b: initial_byte_t = h11._1;
                                                let i12: usize =
                                                    if
                                                    b.major_type == cbor_major_type_byte_string
                                                    ||
                                                    b.major_type == cbor_major_type_text_string
                                                    { argument_as_uint64(h11._1, h11._2) as usize }
                                                    else
                                                    { 0usize };
                                                let _letpattern12: (&[u8], &[u8]) =
                                                    tl1.split_at(i12);
                                                let lc1: &[u8] = _letpattern12.0;
                                                let tl1·: &[u8] = _letpattern12.1;
                                                let n·2: usize =
                                                    (impl_remaining_data_items_header(h11)).wrapping_add(
                                                        n20.wrapping_sub(1usize)
                                                    );
                                                let b0: initial_byte_t = h21._1;
                                                let i13: usize =
                                                    if
                                                    b0.major_type == cbor_major_type_byte_string
                                                    ||
                                                    b0.major_type == cbor_major_type_text_string
                                                    { argument_as_uint64(h21._1, h21._2) as usize }
                                                    else
                                                    { 0usize };
                                                let _letpattern13: (&[u8], &[u8]) =
                                                    tl2.split_at(i13);
                                                let lc2: &[u8] = _letpattern13.0;
                                                let tl2·: &[u8] = _letpattern13.1;
                                                let mt12: u8 = get_header_major_type(h11);
                                                let __anf0: bool =
                                                    if mt12 == cbor_major_type_simple_value
                                                    {
                                                        let sv1: u8 =
                                                            match
                                                            dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                h11
                                                            )
                                                            {
                                                                long_argument::LongArgumentOther =>
                                                                  (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                      h11
                                                                  )).additional_info,
                                                                long_argument::LongArgumentSimpleValue
                                                                { v }
                                                                => v,
                                                                _ =>
                                                                  panic!(
                                                                      "Incomplete pattern matching"
                                                                  )
                                                            };
                                                        let sv2: u8 =
                                                            match
                                                            dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                h21
                                                            )
                                                            {
                                                                long_argument::LongArgumentOther =>
                                                                  (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                      h21
                                                                  )).additional_info,
                                                                long_argument::LongArgumentSimpleValue
                                                                { v }
                                                                => v,
                                                                _ =>
                                                                  panic!(
                                                                      "Incomplete pattern matching"
                                                                  )
                                                            };
                                                        sv1 == sv2
                                                    }
                                                    else
                                                    {
                                                        let len: u64 =
                                                            argument_as_uint64(
                                                                dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                    h11
                                                                ),
                                                                dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                    h11
                                                                )
                                                            );
                                                        let len2: u64 =
                                                            argument_as_uint64(
                                                                dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                    h21
                                                                ),
                                                                dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                                                    h21
                                                                )
                                                            );
                                                        if len != len2
                                                        { false }
                                                        else if
                                                        mt12 == cbor_major_type_byte_string
                                                        ||
                                                        mt12 == cbor_major_type_text_string
                                                        {
                                                            let cmp: i16 =
                                                                lex_compare_bytes(lc1, lc2);
                                                            cmp == 0i16
                                                        }
                                                        else
                                                        { mt12 != cbor_major_type_map }
                                                    };
                                                if __anf0
                                                {
                                                    (&mut pn4)[0usize] = n·2;
                                                    (&mut pl12)[0usize] = tl1·;
                                                    (&mut pl21)[0usize] = tl2·
                                                }
                                                else
                                                {
                                                    (&mut pres4)[0usize] =
                                                        option__bool::Some { v: false }
                                                }
                                            }
                                        }
                                    }
                                };
                                let __anf0: option__bool = (&pres4)[0usize];
                                (&mut pres2)[0usize] = __anf0;
                                (&mut pcont)[0usize] = false
                            }
                            else
                            {
                                (&mut pll)[0usize] = lt·1;
                                (&mut pn2)[0usize] = n·1
                            }
                        }
                    };
                    let res10: option__bool = (&pres2)[0usize];
                    if eq_Some_true(res10)
                    {
                        (&mut pl1)[0usize] = lt·;
                        (&mut pn1)[0usize] = n·
                    }
                    else
                    { (&mut pres1)[0usize] = res10 }
                };
                (&pres1)[0usize]
            }
            else
            { res }
        }
    }
    else
    { option__bool::Some { v: false } }
}

fn impl_check_equiv_list_basic(
    map_bound: option__size_t,
    n1: usize,
    l1: &[u8],
    n2: usize,
    l2: &[u8]
) ->
    option__bool
{
    if n1 != n2
    { option__bool::Some { v: false } }
    else
    {
        let mut pn: [usize; 1] = [n1; 1usize];
        let mut pl1: [&[u8]; 1] = [l1; 1usize];
        let mut pl2: [&[u8]; 1] = [l2; 1usize];
        let mut pres: [option__bool; 1] = [option__bool::Some { v: true }; 1usize];
        while
        true
        {
            let res: option__bool = (&pres)[0usize];
            let n: usize = (&pn)[0usize];
            if ! (eq_Some_true(res) && n > 0usize) { break };
            let l1·: &[u8] = (&pl1)[0usize];
            let l2·: &[u8] = (&pl2)[0usize];
            let r: option__bool = impl_check_equiv_map_hd_basic(map_bound, l1·, l2·);
            if match r { option__bool::None => true, _ => false }
            { (&mut pres)[0usize] = r }
            else
            {
                let n0: usize = (&pn)[0usize];
                if eq_Some_true(r)
                {
                    let n·: usize = n0.wrapping_sub(1usize);
                    let i: usize = jump_raw_data_item(l1·, 0usize);
                    let _letpattern: (&[u8], &[u8]) = l1·.split_at(i);
                    let tl1: &[u8] =
                        {
                            let _input1: &[u8] = _letpattern.0;
                            let input2: &[u8] = _letpattern.1;
                            input2
                        };
                    let i1: usize = jump_raw_data_item(l2·, 0usize);
                    let _letpattern1: (&[u8], &[u8]) = l2·.split_at(i1);
                    let tl2: &[u8] =
                        {
                            let _input1: &[u8] = _letpattern1.0;
                            let input2: &[u8] = _letpattern1.1;
                            input2
                        };
                    (&mut pn)[0usize] = n·;
                    (&mut pl1)[0usize] = tl1;
                    (&mut pl2)[0usize] = tl2
                }
                else
                {
                    let i: usize = jump_header(l1·, 0usize);
                    let _letpattern: (&[u8], &[u8]) = l1·.split_at(i);
                    let hd1: &[u8] = _letpattern.0;
                    let tl1: &[u8] = _letpattern.1;
                    let
                    h1:
                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                    =
                        read_header(hd1);
                    let mt1: u8 = get_header_major_type(h1);
                    let i1: usize = jump_header(l2·, 0usize);
                    let _letpattern1: (&[u8], &[u8]) = l2·.split_at(i1);
                    let hd2: &[u8] = _letpattern1.0;
                    let tl2: &[u8] = _letpattern1.1;
                    let
                    h2:
                    dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                    =
                        read_header(hd2);
                    let mt2: u8 = get_header_major_type(h2);
                    if mt1 != mt2
                    { (&mut pres)[0usize] = option__bool::Some { v: false } }
                    else
                    {
                        let b: initial_byte_t = h1._1;
                        let i2: usize =
                            if
                            b.major_type == cbor_major_type_byte_string
                            ||
                            b.major_type == cbor_major_type_text_string
                            { argument_as_uint64(h1._1, h1._2) as usize }
                            else
                            { 0usize };
                        let _letpattern2: (&[u8], &[u8]) = tl1.split_at(i2);
                        let lc1: &[u8] = _letpattern2.0;
                        let tl1·: &[u8] = _letpattern2.1;
                        let n·: usize =
                            (impl_remaining_data_items_header(h1)).wrapping_add(
                                n0.wrapping_sub(1usize)
                            );
                        let b0: initial_byte_t = h2._1;
                        let i3: usize =
                            if
                            b0.major_type == cbor_major_type_byte_string
                            ||
                            b0.major_type == cbor_major_type_text_string
                            { argument_as_uint64(h2._1, h2._2) as usize }
                            else
                            { 0usize };
                        let _letpattern3: (&[u8], &[u8]) = tl2.split_at(i3);
                        let lc2: &[u8] = _letpattern3.0;
                        let tl2·: &[u8] = _letpattern3.1;
                        let mt11: u8 = get_header_major_type(h1);
                        let __anf0: bool =
                            if mt11 == cbor_major_type_simple_value
                            {
                                let sv1: u8 =
                                    match
                                    dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                        h1
                                    )
                                    {
                                        long_argument::LongArgumentOther =>
                                          (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                              h1
                                          )).additional_info,
                                        long_argument::LongArgumentSimpleValue { v } => v,
                                        _ => panic!("Incomplete pattern matching")
                                    };
                                let sv2: u8 =
                                    match
                                    dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                        h2
                                    )
                                    {
                                        long_argument::LongArgumentOther =>
                                          (dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                              h2
                                          )).additional_info,
                                        long_argument::LongArgumentSimpleValue { v } => v,
                                        _ => panic!("Incomplete pattern matching")
                                    };
                                sv1 == sv2
                            }
                            else
                            {
                                let len: u64 =
                                    argument_as_uint64(
                                        dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                            h1
                                        ),
                                        dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                            h1
                                        )
                                    );
                                let len2: u64 =
                                    argument_as_uint64(
                                        dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                            h2
                                        ),
                                        dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                            h2
                                        )
                                    );
                                if len != len2
                                { false }
                                else if
                                mt11 == cbor_major_type_byte_string
                                ||
                                mt11 == cbor_major_type_text_string
                                {
                                    let cmp: i16 = lex_compare_bytes(lc1, lc2);
                                    cmp == 0i16
                                }
                                else
                                { mt11 != cbor_major_type_map }
                            };
                        if __anf0
                        {
                            (&mut pn)[0usize] = n·;
                            (&mut pl1)[0usize] = tl1·;
                            (&mut pl2)[0usize] = tl2·
                        }
                        else
                        { (&mut pres)[0usize] = option__bool::Some { v: false } }
                    }
                }
            }
        };
        (&pres)[0usize]
    }
}

fn impl_check_equiv_basic(map_bound: option__size_t, l1: &[u8], l2: &[u8]) -> option__bool
{
    if 1usize == 0usize
    { option__bool::Some { v: true } }
    else
    { impl_check_equiv_list_basic(map_bound, 1usize, l1, 1usize, l2) }
}

fn impl_check_valid_basic(map_bound: option__size_t, strict_bound_check: bool, l1: &[u8]) ->
    bool
{
    let mut pn: [usize; 1] = [1usize; 1usize];
    let mut pres: [bool; 1] = [true; 1usize];
    let mut ppi: [&[u8]; 1] = [l1; 1usize];
    while
    true
    {
        let res: bool = (&pres)[0usize];
        let n: usize = (&pn)[0usize];
        if ! (res && n > 0usize) { break };
        let n0: usize = (&pn)[0usize];
        let pi: &[u8] = (&ppi)[0usize];
        let i: usize = jump_header(pi, 0usize);
        let _letpattern: (&[u8], &[u8]) = pi.split_at(i);
        let res0: bool =
            {
                let ah: &[u8] = _letpattern.0;
                let _a1: &[u8] = _letpattern.1;
                let
                h:
                dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                =
                    read_header(ah);
                if get_header_major_type(h) == cbor_major_type_map
                {
                    let i1: usize = jump_raw_data_item(pi, 0usize);
                    let _letpattern1: (&[u8], &[u8]) = pi.split_at(i1);
                    let hd: &[u8] =
                        {
                            let input1: &[u8] = _letpattern1.0;
                            let _input2: &[u8] = _letpattern1.1;
                            input1
                        };
                    let
                    mut
                    ph:
                    [dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument;
                    1]
                    =
                        [h; 1usize];
                    let i2: usize = jump_header(hd, 0usize);
                    let _letpattern2: (&[u8], &[u8]) = hd.split_at(i2);
                    let c: &[u8] =
                        {
                            let ph1: &[u8] = _letpattern2.0;
                            let outc: &[u8] = _letpattern2.1;
                            let
                            h1:
                            dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
                            =
                                read_header(ph1);
                            (&mut ph)[0usize] = h1;
                            outc
                        };
                    let mut pl: [&[u8]; 1] = [c; 1usize];
                    let mut pn1: [usize; 1] =
                        [argument_as_uint64(
                                dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                    h
                                ),
                                dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
                                    h
                                )
                            )
                            as
                            usize;
                            1usize];
                    let mut pres1: [option__bool; 1] = [option__bool::Some { v: true }; 1usize];
                    while
                    true
                    {
                        let n1: usize = (&pn1)[0usize];
                        let res0: option__bool = (&pres1)[0usize];
                        if ! (n1 > 0usize && eq_Some_true(res0)) { break };
                        let n10: usize = (&pn1)[0usize];
                        let n·: usize = n10.wrapping_sub(1usize);
                        let l: &[u8] = (&pl)[0usize];
                        let i3: usize = jump_raw_data_item(l, 0usize);
                        let _letpattern3: (&[u8], &[u8]) = l.split_at(i3);
                        let lh: &[u8] = _letpattern3.0;
                        let lt: &[u8] = _letpattern3.1;
                        let i4: usize = jump_raw_data_item(lt, 0usize);
                        let _letpattern4: (&[u8], &[u8]) = lt.split_at(i4);
                        let _lv: &[u8] = _letpattern4.0;
                        let lt·: &[u8] = _letpattern4.1;
                        let mut pl1: [&[u8]; 1] = [lt·; 1usize];
                        let mut pn2: [usize; 1] = [n·; 1usize];
                        let mut pres2: [option__bool; 1] =
                            [option__bool::Some { v: false }; 1usize];
                        while
                        true
                        {
                            let n2: usize = (&pn2)[0usize];
                            let res1: option__bool = (&pres2)[0usize];
                            if ! (n2 > 0usize && eq_Some_false(res1)) { break };
                            let n20: usize = (&pn2)[0usize];
                            let n·1: usize = n20.wrapping_sub(1usize);
                            let l2: &[u8] = (&pl1)[0usize];
                            let i5: usize = jump_raw_data_item(l2, 0usize);
                            let _letpattern5: (&[u8], &[u8]) = l2.split_at(i5);
                            let lh1: &[u8] = _letpattern5.0;
                            let lt1: &[u8] = _letpattern5.1;
                            let res2: option__bool = impl_check_equiv_basic(map_bound, lh, lh1);
                            if eq_Some_false(res2)
                            {
                                let i6: usize = jump_raw_data_item(lt1, 0usize);
                                let _letpattern6: (&[u8], &[u8]) = lt1.split_at(i6);
                                let _lv1: &[u8] = _letpattern6.0;
                                let lt·1: &[u8] = _letpattern6.1;
                                (&mut pl1)[0usize] = lt·1;
                                (&mut pn2)[0usize] = n·1
                            }
                            else
                            { (&mut pres2)[0usize] = res2 }
                        };
                        let res1: option__bool = (&pres2)[0usize];
                        if match res1 { option__bool::None => true, _ => false }
                        { (&mut pres1)[0usize] = option__bool::None }
                        else if
                        match res1
                        {
                            option__bool::Some { v } => v,
                            _ => panic!("Incomplete pattern matching")
                        }
                        { (&mut pres1)[0usize] = option__bool::Some { v: false } }
                        else
                        {
                            let __anf0: bool =
                                impl_check_map_depth_opt(
                                    if strict_bound_check
                                    { map_bound }
                                    else
                                    { option__size_t::None },
                                    1usize,
                                    lh
                                );
                            if __anf0
                            {
                                (&mut pn1)[0usize] = n·;
                                (&mut pl)[0usize] = lt·
                            }
                            else
                            { (&mut pres1)[0usize] = option__bool::None }
                        }
                    };
                    let res0: option__bool = (&pres1)[0usize];
                    eq_Some_true(res0)
                }
                else
                { true }
            };
        if ! res0
        { (&mut pres)[0usize] = false }
        else
        {
            let off1: usize = jump_header(pi, 0usize);
            let _letpattern1: (&[u8], &[u8]) = pi.split_at(0usize);
            let input·: &[u8] =
                {
                    let _input1: &[u8] = _letpattern1.0;
                    let input23: &[u8] = _letpattern1.1;
                    let consumed: usize = off1.wrapping_sub(0usize);
                    let _letpattern2: (&[u8], &[u8]) = input23.split_at(consumed);
                    let input2: &[u8] = _letpattern2.0;
                    let _input3: &[u8] = _letpattern2.1;
                    input2
                };
            let
            x: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
            =
                read_header(input·);
            let b: initial_byte_t = x._1;
            let i1: usize =
                if
                b.major_type == cbor_major_type_byte_string
                ||
                b.major_type == cbor_major_type_text_string
                { off1.wrapping_add(argument_as_uint64(x._1, x._2) as usize) }
                else
                { off1 };
            let _letpattern2: (&[u8], &[u8]) = pi.split_at(i1);
            let ph: &[u8] = _letpattern2.0;
            let pc: &[u8] = _letpattern2.1;
            let unused: usize = pc.len();
            crate::lowstar::ignore::ignore::<usize>(unused);
            let count: usize = jump_recursive_step_count_leaf(ph);
            let n·: usize = n0.wrapping_sub(1usize).wrapping_add(count);
            (&mut pn)[0usize] = n·;
            (&mut ppi)[0usize] = pc
        }
    };
    (&pres)[0usize]
}

fn impl_list_for_all_with_overflow_setoid_assoc_eq_with_overflow_basic(
    nl1: usize,
    l1: &[u8],
    nl2: usize,
    l2: &[u8]
) ->
    option__bool
{
    let mut pl: [&[u8]; 1] = [l2; 1usize];
    let mut pn: [usize; 1] = [nl2; 1usize];
    let mut pres: [option__bool; 1] = [option__bool::Some { v: true }; 1usize];
    while
    true
    {
        let n: usize = (&pn)[0usize];
        let res: option__bool = (&pres)[0usize];
        if ! (n > 0usize && eq_Some_true(res)) { break };
        let l: &[u8] = (&pl)[0usize];
        let n0: usize = (&pn)[0usize];
        let n·: usize = n0.wrapping_sub(1usize);
        let i: usize = jump_raw_data_item(l, 0usize);
        let _letpattern: (&[u8], &[u8]) = l.split_at(i);
        let lh: &[u8] = _letpattern.0;
        let lt: &[u8] = _letpattern.1;
        let i1: usize = jump_raw_data_item(lt, 0usize);
        let _letpattern1: (&[u8], &[u8]) = lt.split_at(i1);
        let lv: &[u8] = _letpattern1.0;
        let lt·: &[u8] = _letpattern1.1;
        let mut pll: [&[u8]; 1] = [l1; 1usize];
        let mut pn1: [usize; 1] = [nl1; 1usize];
        let mut pres1: [option__bool; 1] = [option__bool::Some { v: false }; 1usize];
        let mut pcont: [bool; 1] = [true; 1usize];
        while
        true
        {
            let n1: usize = (&pn1)[0usize];
            let res0: option__bool = (&pres1)[0usize];
            let cont: bool = (&pcont)[0usize];
            if ! (n1 > 0usize && eq_Some_false(res0) && cont) { break };
            let l3: &[u8] = (&pll)[0usize];
            let n10: usize = (&pn1)[0usize];
            let n·1: usize = n10.wrapping_sub(1usize);
            let i2: usize = jump_raw_data_item(l3, 0usize);
            let _letpattern2: (&[u8], &[u8]) = l3.split_at(i2);
            let lh1: &[u8] = _letpattern2.0;
            let lt1: &[u8] = _letpattern2.1;
            let res1: option__bool = impl_check_equiv_basic(option__size_t::None, lh, lh1);
            if match res1 { option__bool::None => true, _ => false }
            { (&mut pres1)[0usize] = res1 }
            else
            {
                let i3: usize = jump_raw_data_item(lt1, 0usize);
                let _letpattern3: (&[u8], &[u8]) = lt1.split_at(i3);
                let lv1: &[u8] = _letpattern3.0;
                let lt·1: &[u8] = _letpattern3.1;
                if
                match res1
                { option__bool::Some { v } => v, _ => panic!("Incomplete pattern matching") }
                {
                    let __anf0: option__bool =
                        impl_check_equiv_basic(option__size_t::None, lv, lv1);
                    (&mut pres1)[0usize] = __anf0;
                    (&mut pcont)[0usize] = false
                }
                else
                {
                    (&mut pll)[0usize] = lt·1;
                    (&mut pn1)[0usize] = n·1
                }
            }
        };
        let res0: option__bool = (&pres1)[0usize];
        if eq_Some_true(res0)
        {
            (&mut pl)[0usize] = lt·;
            (&mut pn)[0usize] = n·
        }
        else
        { (&mut pres)[0usize] = res0 }
    };
    (&pres)[0usize]
}

fn cbor_match_equal_serialized_tagged(c1: cbor_serialized, c2: cbor_serialized) -> bool
{
    if c1.cbor_serialized_header.value != c2.cbor_serialized_header.value
    { false }
    else
    {
        let res: option__bool =
            impl_check_equiv_basic(
                option__size_t::None,
                c1.cbor_serialized_payload,
                c2.cbor_serialized_payload
            );
        eq_Some_true(res)
    }
}

fn cbor_match_compare_serialized_array(c1: cbor_serialized, c2: cbor_serialized) -> bool
{
    let n1: usize = c1.cbor_serialized_header.value as usize;
    let n2: usize = c2.cbor_serialized_header.value as usize;
    let res: option__bool =
        impl_check_equiv_list_basic(
            option__size_t::None,
            n1,
            c1.cbor_serialized_payload,
            n2,
            c2.cbor_serialized_payload
        );
    eq_Some_true(res)
}

fn cbor_match_compare_serialized_map(c1: cbor_serialized, c2: cbor_serialized) -> bool
{
    let n1: usize = c1.cbor_serialized_header.value as usize;
    let n2: usize = c2.cbor_serialized_header.value as usize;
    let res21: option__bool =
        impl_list_for_all_with_overflow_setoid_assoc_eq_with_overflow_basic(
            n2,
            c2.cbor_serialized_payload,
            n1,
            c1.cbor_serialized_payload
        );
    if eq_Some_true(res21)
    {
        let res12: option__bool =
            impl_list_for_all_with_overflow_setoid_assoc_eq_with_overflow_basic(
                n1,
                c1.cbor_serialized_payload,
                n2,
                c2.cbor_serialized_payload
            );
        eq_Some_true(res12)
    }
    else
    { false }
}

fn impl_major_type_with_depth(x: cbor_raw) -> u8
{
    match x
    {
        cbor_raw::CBOR_Case_Simple { .. } => cbor_major_type_simple_value,
        cbor_raw::CBOR_Case_Int { .. } =>
          match x
          {
              cbor_raw::CBOR_Case_Int { v: c· } => c·.cbor_int_type,
              _ => panic!("Incomplete pattern matching")
          },
        cbor_raw::CBOR_Case_String { .. } =>
          match x
          {
              cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_type,
              _ => panic!("Incomplete pattern matching")
          },
        cbor_raw::CBOR_Case_Tagged { .. } => cbor_major_type_tagged,
        cbor_raw::CBOR_Case_Serialized_Tagged { .. } => cbor_major_type_tagged,
        cbor_raw::CBOR_Case_Array { .. } => cbor_major_type_array,
        cbor_raw::CBOR_Case_Serialized_Array { .. } => cbor_major_type_array,
        cbor_raw::CBOR_Case_Map { .. } => cbor_major_type_map,
        cbor_raw::CBOR_Case_Serialized_Map { .. } => cbor_major_type_map,
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_match_tagged_get_tag_with_depth0(c: cbor_raw) -> raw_uint64
{
    match c
    {
        cbor_raw::CBOR_Case_Tagged { v: a } => a.cbor_tagged_tag,
        cbor_raw::CBOR_Case_Serialized_Tagged { .. } =>
          match c
          {
              cbor_raw::CBOR_Case_Tagged { v: c· } => c·.cbor_tagged_tag,
              cbor_raw::CBOR_Case_Serialized_Tagged { v: c· } => c·.cbor_serialized_header,
              _ => panic!("Incomplete pattern matching")
          },
        _ => panic!("Incomplete pattern matching")
    }
}

fn cbor_match_array_get_length_with_depth0(c: cbor_raw) -> raw_uint64
{
    match c
    {
        cbor_raw::CBOR_Case_Array { v: a } =>
          raw_uint64 { size: a.cbor_array_length_size, value: (a.cbor_array_ptr).len() as u64 },
        cbor_raw::CBOR_Case_Serialized_Array { .. } =>
          match c
          {
              cbor_raw::CBOR_Case_Array { v: c· } =>
                raw_uint64
                { size: c·.cbor_array_length_size, value: (c·.cbor_array_ptr).len() as u64 },
              cbor_raw::CBOR_Case_Serialized_Array { v: c· } => c·.cbor_serialized_header,
              _ => panic!("Incomplete pattern matching")
          },
        _ => panic!("Incomplete pattern matching")
    }
}

pub(crate) fn cbor_nondet_equiv_with_depth(x1: cbor_raw, x2: cbor_raw) -> bool
{
    let mt1: u8 = impl_major_type_with_depth(x1);
    let mt2: u8 = impl_major_type_with_depth(x2);
    if mt1 != mt2
    { false }
    else if mt1 == cbor_major_type_simple_value
    {
        let w1: u8 =
            match x1
            {
                cbor_raw::CBOR_Case_Simple { v: res } => res,
                _ => panic!("Incomplete pattern matching")
            };
        let w2: u8 =
            match x2
            {
                cbor_raw::CBOR_Case_Simple { v: res } => res,
                _ => panic!("Incomplete pattern matching")
            };
        w1 == w2
    }
    else if mt1 == cbor_major_type_uint64 || mt1 == cbor_major_type_neg_int64
    {
        let w1: raw_uint64 =
            match x1
            {
                cbor_raw::CBOR_Case_Int { v: c· } =>
                  raw_uint64 { size: c·.cbor_int_size, value: c·.cbor_int_value },
                _ => panic!("Incomplete pattern matching")
            };
        let w2: raw_uint64 =
            match x2
            {
                cbor_raw::CBOR_Case_Int { v: c· } =>
                  raw_uint64 { size: c·.cbor_int_size, value: c·.cbor_int_value },
                _ => panic!("Incomplete pattern matching")
            };
        w1.value == w2.value
    }
    else if mt1 == cbor_major_type_byte_string || mt1 == cbor_major_type_text_string
    {
        let len1: raw_uint64 =
            match x1
            {
                cbor_raw::CBOR_Case_String { v: c· } =>
                  raw_uint64
                  { size: c·.cbor_string_size, value: (c·.cbor_string_ptr).len() as u64 },
                _ => panic!("Incomplete pattern matching")
            };
        let len2: raw_uint64 =
            match x2
            {
                cbor_raw::CBOR_Case_String { v: c· } =>
                  raw_uint64
                  { size: c·.cbor_string_size, value: (c·.cbor_string_ptr).len() as u64 },
                _ => panic!("Incomplete pattern matching")
            };
        if len1.value != len2.value
        { false }
        else
        {
            let w1: &[u8] =
                match x1
                {
                    cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_ptr,
                    _ => panic!("Incomplete pattern matching")
                };
            let w2: &[u8] =
                match x2
                {
                    cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_ptr,
                    _ => panic!("Incomplete pattern matching")
                };
            let res: i16 = lex_compare_bytes(w1, w2);
            res == 0i16
        }
    }
    else if mt1 == cbor_major_type_tagged
    {
        if
        match (x1,x2)
        {
            (
                cbor_raw::CBOR_Case_Serialized_Tagged
                { .. },cbor_raw::CBOR_Case_Serialized_Tagged
                { .. }
            )
            => true,
            _ => false
        }
        {
            match x1
            {
                cbor_raw::CBOR_Case_Serialized_Tagged { v: cs1 } =>
                  match x2
                  {
                      cbor_raw::CBOR_Case_Serialized_Tagged { v: cs2 } =>
                        cbor_match_equal_serialized_tagged(cs1, cs2),
                      _ => panic!("Incomplete pattern matching")
                  },
                _ => panic!("Incomplete pattern matching")
            }
        }
        else
        {
            let tag1: raw_uint64 = cbor_match_tagged_get_tag_with_depth0(x1);
            let tag2: raw_uint64 = cbor_match_tagged_get_tag_with_depth0(x2);
            if tag1.value != tag2.value
            { false }
            else
            {
                let w1: cbor_raw = cbor_match_tagged_get_payload_with_depth(x1);
                let w2: cbor_raw = cbor_match_tagged_get_payload_with_depth(x2);
                cbor_nondet_equiv_with_depth(w1, w2)
            }
        }
    }
    else if mt1 == cbor_major_type_array
    {
        if
        match (x1,x2)
        {
            (
                cbor_raw::CBOR_Case_Serialized_Array
                { .. },cbor_raw::CBOR_Case_Serialized_Array
                { .. }
            )
            => true,
            _ => false
        }
        {
            match x1
            {
                cbor_raw::CBOR_Case_Serialized_Array { v: cs1 } =>
                  match x2
                  {
                      cbor_raw::CBOR_Case_Serialized_Array { v: cs2 } =>
                        cbor_match_compare_serialized_array(cs1, cs2),
                      _ => panic!("Incomplete pattern matching")
                  },
                _ => panic!("Incomplete pattern matching")
            }
        }
        else
        {
            let len1: raw_uint64 = cbor_match_array_get_length_with_depth0(x1);
            let len2: raw_uint64 = cbor_match_array_get_length_with_depth0(x2);
            if len1.value != len2.value
            { false }
            else
            {
                let i1: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw =
                    cbor_array_iterator_init_with_depth(x1);
                let i2: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw =
                    cbor_array_iterator_init_with_depth(x2);
                let mut pi1: [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw; 1] = [i1; 1usize];
                let mut pi2: [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw; 1] = [i2; 1usize];
                let mut pres: [bool; 1] = [true; 1usize];
                while
                true
                {
                    let res: bool = (&pres)[0usize];
                    let i11: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw = (&pi1)[0usize];
                    let __anf0: bool = cbor_array_iterator_is_empty_with_depth(i11);
                    if ! (res && ! __anf0) { break };
                    let y1: cbor_raw = cbor_array_iterator_next_with_depth(&mut pi1);
                    let y2: cbor_raw = cbor_array_iterator_next_with_depth(&mut pi2);
                    let __anf00: bool = cbor_nondet_equiv_with_depth(y1, y2);
                    (&mut pres)[0usize] = __anf00
                };
                (&pres)[0usize]
            }
        }
    }
    else if
    match (x1,x2)
    {
        (cbor_raw::CBOR_Case_Serialized_Map { .. },cbor_raw::CBOR_Case_Serialized_Map { .. }) =>
          true,
        _ => false
    }
    {
        match x1
        {
            cbor_raw::CBOR_Case_Serialized_Map { v: cs1 } =>
              match x2
              {
                  cbor_raw::CBOR_Case_Serialized_Map { v: cs2 } =>
                    cbor_match_compare_serialized_map(cs1, cs2),
                  _ => panic!("Incomplete pattern matching")
              },
            _ => panic!("Incomplete pattern matching")
        }
    }
    else
    {
        let i1: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry =
            cbor_map_iterator_init_with_depth(x1);
        let i2: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry =
            cbor_map_iterator_init_with_depth(x2);
        let mut pi2: [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry; 1] = [i1; 1usize];
        let mut pres: [bool; 1] = [true; 1usize];
        while
        true
        {
            let res: bool = (&pres)[0usize];
            let i21: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry = (&pi2)[0usize];
            let __anf0: bool = cbor_map_iterator_is_empty_with_depth(i21);
            if ! (res && ! __anf0) { break };
            let x21: cbor_map_entry = cbor_map_iterator_next_with_depth(&mut pi2);
            let mut pi1: [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry; 1] = [i2; 1usize];
            let mut pres1: [option__bool; 1] = [option__bool::None; 1usize];
            while
            true
            {
                let res0: option__bool = (&pres1)[0usize];
                let i11: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry = (&pi1)[0usize];
                let __anf00: bool = cbor_map_iterator_is_empty_with_depth(i11);
                if ! (match res0 { option__bool::None => true, _ => false } && ! __anf00) { break };
                let x11: cbor_map_entry = cbor_map_iterator_next_with_depth(&mut pi1);
                let __anf01: bool =
                    cbor_nondet_equiv_with_depth(x21.cbor_map_entry_key, x11.cbor_map_entry_key);
                if __anf01
                {
                    let __anf010: bool =
                        cbor_nondet_equiv_with_depth(
                            x21.cbor_map_entry_value,
                            x11.cbor_map_entry_value
                        );
                    (&mut pres1)[0usize] = option__bool::Some { v: __anf010 }
                }
            };
            let __anf00: option__bool = (&pres1)[0usize];
            let __anf01: bool = eq_Some_true(__anf00);
            (&mut pres)[0usize] = __anf01
        };
        let __anf0: bool = (&pres)[0usize];
        if ! __anf0
        { false }
        else
        {
            let mut pi21: [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry; 1] = [i2; 1usize];
            let mut pres1: [bool; 1] = [true; 1usize];
            while
            true
            {
                let res: bool = (&pres1)[0usize];
                let i21: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry = (&pi21)[0usize];
                let __anf01: bool = cbor_map_iterator_is_empty_with_depth(i21);
                if ! (res && ! __anf01) { break };
                let x21: cbor_map_entry = cbor_map_iterator_next_with_depth(&mut pi21);
                let mut pi1: [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry; 1] =
                    [i1; 1usize];
                let mut pres2: [option__bool; 1] = [option__bool::None; 1usize];
                while
                true
                {
                    let res0: option__bool = (&pres2)[0usize];
                    let i11: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry = (&pi1)[0usize];
                    let __anf010: bool = cbor_map_iterator_is_empty_with_depth(i11);
                    if ! (match res0 { option__bool::None => true, _ => false } && ! __anf010)
                    { break };
                    let x11: cbor_map_entry = cbor_map_iterator_next_with_depth(&mut pi1);
                    let __anf011: bool =
                        cbor_nondet_equiv_with_depth(x21.cbor_map_entry_key, x11.cbor_map_entry_key);
                    if __anf011
                    {
                        let __anf02: bool =
                            cbor_nondet_equiv_with_depth(
                                x21.cbor_map_entry_value,
                                x11.cbor_map_entry_value
                            );
                        (&mut pres2)[0usize] = option__bool::Some { v: __anf02 }
                    }
                };
                let __anf010: option__bool = (&pres2)[0usize];
                let __anf02: bool = eq_Some_true(__anf010);
                (&mut pres1)[0usize] = __anf02
            };
            (&pres1)[0usize]
        }
    }
}

fn cbor_nondet_equiv(x1: cbor_raw, x2: cbor_raw) -> bool
{ cbor_nondet_equiv_with_depth(x1, x2) }

fn cbor_nondet_no_setoid_repeats(x: &[cbor_map_entry]) -> bool
{
    let mut pn1: [usize; 1] = [0usize; 1usize];
    let mut pres: [bool; 1] = [true; 1usize];
    while
    true
    {
        let res: bool = (&pres)[0usize];
        let __anf0: usize = (&pn1)[0usize];
        if ! (res && __anf0 < x.len()) { break };
        let n1: usize = (&pn1)[0usize];
        let x1: cbor_map_entry = x[n1];
        let n2: usize = n1.wrapping_add(1usize);
        (&mut pn1)[0usize] = n2;
        let mut pn2: [usize; 1] = [n2; 1usize];
        while
        true
        {
            let res0: bool = (&pres)[0usize];
            let __anf00: usize = (&pn2)[0usize];
            if ! (res0 && __anf00 < x.len()) { break };
            let n21: usize = (&pn2)[0usize];
            let x2: cbor_map_entry = x[n21];
            let __anf01: bool = cbor_nondet_equiv(x1.cbor_map_entry_key, x2.cbor_map_entry_key);
            (&mut pres)[0usize] = ! __anf01;
            (&mut pn2)[0usize] = n21.wrapping_add(1usize)
        }
    };
    (&pres)[0usize]
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) struct sip
{ pub v0: u64, pub v1: u64, pub v2: u64, pub v3: u64, pub nw: u64 }

fn sip_round(s: sip) -> sip
{
    let v0: u64 = (s.v0).wrapping_add(s.v1);
    let v1: u64 = (s.v1).wrapping_shl(13u32) | (s.v1).wrapping_shr(51u32);
    let v11: u64 = v1 ^ v0;
    let v01: u64 = v0.wrapping_shl(32u32) | v0.wrapping_shr(32u32);
    let v2: u64 = (s.v2).wrapping_add(s.v3);
    let v3: u64 = (s.v3).wrapping_shl(16u32) | (s.v3).wrapping_shr(48u32);
    let v31: u64 = v3 ^ v2;
    let v02: u64 = v01.wrapping_add(v31);
    let v32: u64 = v31.wrapping_shl(21u32) | v31.wrapping_shr(43u32);
    let v33: u64 = v32 ^ v02;
    let v21: u64 = v2.wrapping_add(v11);
    let v12: u64 = v11.wrapping_shl(17u32) | v11.wrapping_shr(47u32);
    let v13: u64 = v12 ^ v21;
    let v22: u64 = v21.wrapping_shl(32u32) | v21.wrapping_shr(32u32);
    sip { v0: v02, v1: v13, v2: v22, v3: v33, nw: s.nw }
}

fn sip_absorb(s: sip, m: u64) -> sip
{
    let s1: sip = sip_round(sip { v0: s.v0, v1: s.v1, v2: s.v2, v3: s.v3 ^ m, nw: s.nw });
    sip { v0: s1.v0 ^ m, v1: s1.v1, v2: s1.v2, v3: s1.v3, nw: (s.nw).wrapping_add(1u64) }
}

fn sip_fin(s: sip) -> u64
{
    let m: u64 = (s.nw).wrapping_shl(59u32);
    let s1: sip = sip_round(sip { v0: s.v0, v1: s.v1, v2: s.v2, v3: s.v3 ^ m, nw: s.nw });
    let s2: sip = sip { v0: s1.v0 ^ m, v1: s1.v1, v2: s1.v2 ^ 0xffu64, v3: s1.v3, nw: s1.nw };
    let s3: sip = sip_round(sip_round(sip_round(s2)));
    s3.v0 ^ s3.v1 ^ (s3.v2 ^ s3.v3)
}

fn hash_word(b: &[u8], x: usize, c: usize) -> u64
{
    let mut pj: [usize; 1] = [c; 1usize];
    let mut pw: [u64; 1] = [0u64; 1usize];
    while
    true
    {
        let j: usize = (&pj)[0usize];
        if j <= 0usize { break };
        let j0: usize = (&pj)[0usize];
        let w: u64 = (&pw)[0usize];
        let j·: usize = j0.wrapping_sub(1usize);
        let y: u8 = b[x.wrapping_add(j·)];
        (&mut pw)[0usize] = y as u64 | w.wrapping_shl(8u32);
        (&mut pj)[0usize] = j·
    };
    (&pw)[0usize]
}

fn hash_bytes(b: &[u8], st0: sip, o: usize, len: usize) -> sip
{
    let mut pi: [usize; 1] = [0usize; 1usize];
    let mut pst: [sip; 1] = [st0; 1usize];
    while
    true
    {
        let i: usize = (&pi)[0usize];
        if i >= len { break };
        let i0: usize = (&pi)[0usize];
        let st: sip = (&pst)[0usize];
        let rem: usize = len.wrapping_sub(i0);
        let c: usize = if rem < 8usize { rem } else { 8usize };
        let x: usize = o.wrapping_add(i0);
        let w: u64 = hash_word(b, x, c);
        (&mut pst)[0usize] = sip_absorb(st, w);
        (&mut pi)[0usize] = i0.wrapping_add(c)
    };
    (&pst)[0usize]
}

fn hash_leaf(b: &[u8], is_string: bool, st0: sip, o: usize, len: usize) -> sip
{ if is_string { hash_bytes(b, st0, o, len) } else { st0 } }

pub(crate) fn hash_items(
    b: &[u8],
    k0: u64,
    k1: u64,
    st0: sip,
    o0: usize,
    c0: usize,
    pout: &mut [usize]
) ->
    sip
{
    let mut po: [usize; 1] = [o0; 1usize];
    let mut pc: [usize; 1] = [c0; 1usize];
    let mut pst: [sip; 1] = [st0; 1usize];
    while
    true
    {
        let c: usize = (&pc)[0usize];
        if c <= 0usize { break };
        let o: usize = (&po)[0usize];
        let c1: usize = (&pc)[0usize];
        let st: sip = (&pst)[0usize];
        let oh: usize = jump_header(b, o);
        let _letpattern: (&[u8], &[u8]) = b.split_at(o);
        let input·: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input23: &[u8] = _letpattern.1;
                let consumed: usize = oh.wrapping_sub(o);
                let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern1.0;
                let _input3: &[u8] = _letpattern1.1;
                input2
            };
        let
        h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            read_header(input·);
        let mt: u8 = get_header_major_type(h);
        let mt1: u8 = get_header_major_type(h);
        let hval: u64 =
            if mt1 == cbor_major_type_simple_value
            {
                let v: u8 =
                    match h._2
                    {
                        long_argument::LongArgumentOther => h._1.additional_info,
                        long_argument::LongArgumentSimpleValue { v } => v,
                        _ => panic!("Incomplete pattern matching")
                    };
                v as u64
            }
            else if mt1 == cbor_major_type_uint64 || mt1 == cbor_major_type_neg_int64
            {
                let v: raw_uint64 =
                    match h._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    };
                v.value
            }
            else if mt1 == cbor_major_type_byte_string || mt1 == cbor_major_type_text_string
            {
                let v: raw_uint64 =
                    match h._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    };
                v.value
            }
            else if mt1 == cbor_major_type_tagged
            {
                let v: raw_uint64 =
                    match h._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    };
                v.value
            }
            else if mt1 == cbor_major_type_array
            {
                let v: raw_uint64 =
                    match h._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    };
                v.value
            }
            else
            {
                let v: raw_uint64 =
                    match h._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    };
                v.value
            };
        let st1: sip = sip_absorb(sip_absorb(st, mt as u64), hval);
        if mt == cbor_major_type_map
        {
            let k: usize =
                match h._2
                {
                    long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                    long_argument::LongArgumentU16 { v } =>
                      raw_uint64 { size: 2u8, value: v as u64 },
                    long_argument::LongArgumentU32 { v } =>
                      raw_uint64 { size: 3u8, value: v as u64 },
                    long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                    long_argument::LongArgumentOther =>
                      raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                    _ => panic!("Incomplete pattern matching")
                }.value
                as
                usize;
            let mut pi: [usize; 1] = [0usize; 1usize];
            let mut pe: [usize; 1] = [oh; 1usize];
            let mut pacc: [u64; 1] = [0u64; 1usize];
            while
            true
            {
                let i: usize = (&pi)[0usize];
                if i >= k { break };
                let i0: usize = (&pi)[0usize];
                let e: usize = (&pe)[0usize];
                let acc: u64 = (&pacc)[0usize];
                let sk: sip =
                    hash_items(
                        b,
                        k0,
                        k1,
                        sip
                        {
                            v0: k0 ^ 0x736f6d6570736575u64,
                            v1: k1 ^ 0x646f72616e646f6du64,
                            v2: k0 ^ 0x6c7967656e657261u64,
                            v3: k1 ^ 0x7465646279746573u64,
                            nw: 0u64
                        },
                        e,
                        1usize,
                        pout
                    );
                let o1: usize = pout[0usize];
                let sv: sip =
                    hash_items(
                        b,
                        k0,
                        k1,
                        sip
                        {
                            v0: k0 ^ 0x736f6d6570736575u64,
                            v1: k1 ^ 0x646f72616e646f6du64,
                            v2: k0 ^ 0x6c7967656e657261u64,
                            v3: k1 ^ 0x7465646279746573u64,
                            nw: 0u64
                        },
                        o1,
                        1usize,
                        pout
                    );
                let o2: usize = pout[0usize];
                (&mut pacc)[0usize] =
                    acc.wrapping_add(
                        sip_fin(
                            sip_absorb(
                                sip_absorb(
                                    sip
                                    {
                                        v0: k0 ^ 0x736f6d6570736575u64,
                                        v1: k1 ^ 0x646f72616e646f6du64,
                                        v2: k0 ^ 0x6c7967656e657261u64,
                                        v3: k1 ^ 0x7465646279746573u64,
                                        nw: 0u64
                                    },
                                    sip_fin(sk)
                                ),
                                sip_fin(sv)
                            )
                        )
                    );
                (&mut pe)[0usize] = o2;
                (&mut pi)[0usize] = i0.wrapping_add(1usize)
            };
            let e: usize = (&pe)[0usize];
            let acc: u64 = (&pacc)[0usize];
            (&mut pst)[0usize] = sip_absorb(st1, acc);
            (&mut po)[0usize] = e;
            (&mut pc)[0usize] = c1.wrapping_sub(1usize)
        }
        else
        {
            let is_string: bool =
                mt == cbor_major_type_byte_string || mt == cbor_major_type_text_string;
            let leaf: usize =
                if is_string
                {
                    match h._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    as
                    usize
                }
                else
                { 0usize };
            let st2: sip = hash_leaf(b, is_string, st1, oh, leaf);
            let rem: usize = impl_remaining_data_items_header(h);
            (&mut pst)[0usize] = st2;
            (&mut po)[0usize] = oh.wrapping_add(leaf);
            (&mut pc)[0usize] = rem.wrapping_add(c1.wrapping_sub(1usize))
        }
    };
    let o: usize = (&po)[0usize];
    pout[0usize] = o;
    (&pst)[0usize]
}

fn fill_offsets(b: &[u8], ks: &mut [usize], o0: usize) -> usize
{
    let k: usize = ks.len();
    let mut pi: [usize; 1] = [0usize; 1usize];
    let mut po: [usize; 1] = [o0; 1usize];
    while
    true
    {
        let i: usize = (&pi)[0usize];
        if i >= k { break };
        let i0: usize = (&pi)[0usize];
        let o: usize = (&po)[0usize];
        ks[i0] = o;
        let o1: usize = jump_raw_data_item(b, o);
        let o2: usize = jump_raw_data_item(b, o1);
        (&mut pi)[0usize] = i0.wrapping_add(1usize);
        (&mut po)[0usize] = o2
    };
    (&po)[0usize]
}

fn cmp_str(b: &[u8], o1: usize, o2: usize, len: usize) -> i16
{
    let s1: &[u8] = &b[o1..o1.wrapping_add(len)];
    let s2: &[u8] = &b[o2..o2.wrapping_add(len)];
    lex_compare_bytes(s1, s2)
}

fn cmp_leaf(b: &[u8], is_string: bool, o1: usize, o2: usize, len: usize) -> i16
{ if is_string { cmp_str(b, o1, o2, len) } else { 0i16 } }

pub(crate) fn cmp_one(b: &[u8], sc: &mut [usize], x: usize, y: usize) -> i16
{
    let mut po1: [usize; 1] = [x; 1usize];
    let mut po2: [usize; 1] = [y; 1usize];
    let mut pc: [usize; 1] = [1usize; 1usize];
    let mut pres: [i16; 1] = [0i16; 1usize];
    while
    true
    {
        let r: i16 = (&pres)[0usize];
        let c: usize = (&pc)[0usize];
        if ! (r == 0i16 && c > 0usize) { break };
        let o1: usize = (&po1)[0usize];
        let o2: usize = (&po2)[0usize];
        let c0: usize = (&pc)[0usize];
        let oh1: usize = jump_header(b, o1);
        let _letpattern: (&[u8], &[u8]) = b.split_at(o1);
        let input·: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input23: &[u8] = _letpattern.1;
                let consumed: usize = oh1.wrapping_sub(o1);
                let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern1.0;
                let _input3: &[u8] = _letpattern1.1;
                input2
            };
        let
        h1: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            read_header(input·);
        let oh2: usize = jump_header(b, o2);
        let _letpattern1: (&[u8], &[u8]) = b.split_at(o2);
        let input·1: &[u8] =
            {
                let _input1: &[u8] = _letpattern1.0;
                let input23: &[u8] = _letpattern1.1;
                let consumed: usize = oh2.wrapping_sub(o2);
                let _letpattern2: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern2.0;
                let _input3: &[u8] = _letpattern2.1;
                input2
            };
        let
        h2: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            read_header(input·1);
        let mt1: u8 = get_header_major_type(h1);
        let mt2: u8 = get_header_major_type(h2);
        if mt1 != mt2
        {
            let r0: i16 = if mt1 < mt2 { -1i16 } else { 1i16 };
            (&mut pres)[0usize] = r0
        }
        else
        {
            let mt: u8 = get_header_major_type(h1);
            let hc: i16 =
                if mt == cbor_major_type_simple_value
                {
                    if
                    match h1._2
                    {
                        long_argument::LongArgumentOther => h1._1.additional_info,
                        long_argument::LongArgumentSimpleValue { v } => v,
                        _ => panic!("Incomplete pattern matching")
                    }
                    <
                    match h2._2
                    {
                        long_argument::LongArgumentOther => h2._1.additional_info,
                        long_argument::LongArgumentSimpleValue { v } => v,
                        _ => panic!("Incomplete pattern matching")
                    }
                    { -1i16 }
                    else if
                    match h1._2
                    {
                        long_argument::LongArgumentOther => h1._1.additional_info,
                        long_argument::LongArgumentSimpleValue { v } => v,
                        _ => panic!("Incomplete pattern matching")
                    }
                    >
                    match h2._2
                    {
                        long_argument::LongArgumentOther => h2._1.additional_info,
                        long_argument::LongArgumentSimpleValue { v } => v,
                        _ => panic!("Incomplete pattern matching")
                    }
                    { 1i16 }
                    else
                    { 0i16 }
                }
                else if mt == cbor_major_type_uint64 || mt == cbor_major_type_neg_int64
                {
                    if
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    <
                    match h2._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    { -1i16 }
                    else if
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    >
                    match h2._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    { 1i16 }
                    else
                    { 0i16 }
                }
                else if mt == cbor_major_type_byte_string || mt == cbor_major_type_text_string
                {
                    if
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    <
                    match h2._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    { -1i16 }
                    else if
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    >
                    match h2._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    { 1i16 }
                    else
                    { 0i16 }
                }
                else if mt == cbor_major_type_tagged
                {
                    if
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    <
                    match h2._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    { -1i16 }
                    else if
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    >
                    match h2._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    { 1i16 }
                    else
                    { 0i16 }
                }
                else if mt == cbor_major_type_array
                {
                    if
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    <
                    match h2._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    { -1i16 }
                    else if
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    >
                    match h2._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    { 1i16 }
                    else
                    { 0i16 }
                }
                else if
                match h1._2
                {
                    long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                    long_argument::LongArgumentU16 { v } =>
                      raw_uint64 { size: 2u8, value: v as u64 },
                    long_argument::LongArgumentU32 { v } =>
                      raw_uint64 { size: 3u8, value: v as u64 },
                    long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                    long_argument::LongArgumentOther =>
                      raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                    _ => panic!("Incomplete pattern matching")
                }.value
                <
                match h2._2
                {
                    long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                    long_argument::LongArgumentU16 { v } =>
                      raw_uint64 { size: 2u8, value: v as u64 },
                    long_argument::LongArgumentU32 { v } =>
                      raw_uint64 { size: 3u8, value: v as u64 },
                    long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                    long_argument::LongArgumentOther =>
                      raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                    _ => panic!("Incomplete pattern matching")
                }.value
                { -1i16 }
                else if
                match h1._2
                {
                    long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                    long_argument::LongArgumentU16 { v } =>
                      raw_uint64 { size: 2u8, value: v as u64 },
                    long_argument::LongArgumentU32 { v } =>
                      raw_uint64 { size: 3u8, value: v as u64 },
                    long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                    long_argument::LongArgumentOther =>
                      raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                    _ => panic!("Incomplete pattern matching")
                }.value
                >
                match h2._2
                {
                    long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                    long_argument::LongArgumentU16 { v } =>
                      raw_uint64 { size: 2u8, value: v as u64 },
                    long_argument::LongArgumentU32 { v } =>
                      raw_uint64 { size: 3u8, value: v as u64 },
                    long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                    long_argument::LongArgumentOther =>
                      raw_uint64 { size: 0u8, value: h2._1.additional_info as u64 },
                    _ => panic!("Incomplete pattern matching")
                }.value
                { 1i16 }
                else
                { 0i16 };
            if hc != 0i16
            { (&mut pres)[0usize] = hc }
            else if mt1 == cbor_major_type_map
            {
                let k: usize =
                    match h1._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    as
                    usize;
                let _letpattern2: (&mut [usize], &mut [usize]) = sc.split_at_mut(k);
                let r0: i16 =
                    {
                        let ks1: &mut [usize] = _letpattern2.0;
                        let r1: &mut [usize] = _letpattern2.1;
                        let _letpattern3: (&mut [usize], &mut [usize]) = r1.split_at_mut(k);
                        let ks2: &mut [usize] = _letpattern3.0;
                        let r2: &mut [usize] = _letpattern3.1;
                        let _letpattern4: (&mut [usize], &mut [usize]) = r2.split_at_mut(k);
                        let tmp: &mut [usize] = _letpattern4.0;
                        let rest: &mut [usize] = _letpattern4.1;
                        let o·: usize = fill_offsets(b, ks1, oh1);
                        let n: usize = ks1.len();
                        let mut pw: [usize; 1] = [1usize; 1usize];
                        let mut pok: [bool; 1] = [true; 1usize];
                        let mut pdone: [bool; 1] = [n <= 1usize; 1usize];
                        while
                        true
                        {
                            let ok: bool = (&pok)[0usize];
                            let done: bool = (&pdone)[0usize];
                            if ! (ok && ! done) { break };
                            let w: usize = (&pw)[0usize];
                            let n1: usize = ks1.len();
                            let mut plo: [usize; 1] = [0usize; 1usize];
                            let mut pok1: [bool; 1] = [true; 1usize];
                            while
                            true
                            {
                                let ok0: bool = (&pok1)[0usize];
                                let lo: usize = (&plo)[0usize];
                                if ! (ok0 && lo < n1) { break };
                                let lo0: usize = (&plo)[0usize];
                                let mid: usize =
                                    if w <= n1.wrapping_sub(lo0) { lo0.wrapping_add(w) } else { n1 };
                                let hi: usize =
                                    if w <= n1.wrapping_sub(mid) { mid.wrapping_add(w) } else { n1 };
                                let mut pi1: [usize; 1] = [lo0; 1usize];
                                let mut pi2: [usize; 1] = [mid; 1usize];
                                let mut pk: [usize; 1] = [lo0; 1usize];
                                let mut pok2: [bool; 1] = [true; 1usize];
                                while
                                true
                                {
                                    let ok1: bool = (&pok2)[0usize];
                                    let i1: usize = (&pi1)[0usize];
                                    let i2: usize = (&pi2)[0usize];
                                    if ! (ok1 && (i1 != mid || i2 != hi)) { break };
                                    let i10: usize = (&pi1)[0usize];
                                    let i20: usize = (&pi2)[0usize];
                                    let k1: usize = (&pk)[0usize];
                                    if i10 == mid
                                    {
                                        let x1: usize = ks1[i20];
                                        tmp[k1] = x1;
                                        (&mut pi2)[0usize] = i20.wrapping_add(1usize);
                                        (&mut pk)[0usize] = k1.wrapping_add(1usize)
                                    }
                                    else if i20 == hi
                                    {
                                        let x1: usize = ks1[i10];
                                        tmp[k1] = x1;
                                        (&mut pi1)[0usize] = i10.wrapping_add(1usize);
                                        (&mut pk)[0usize] = k1.wrapping_add(1usize)
                                    }
                                    else
                                    {
                                        let x1: usize = ks1[i10];
                                        let x2: usize = ks1[i20];
                                        let c1: i16 = cmp_one(b, rest, x1, x2);
                                        if c1 == 0i16
                                        { (&mut pok2)[0usize] = false }
                                        else if c1 < 0i16
                                        {
                                            tmp[k1] = x1;
                                            (&mut pi1)[0usize] = i10.wrapping_add(1usize);
                                            (&mut pk)[0usize] = k1.wrapping_add(1usize)
                                        }
                                        else
                                        {
                                            tmp[k1] = x2;
                                            (&mut pi2)[0usize] = i20.wrapping_add(1usize);
                                            (&mut pk)[0usize] = k1.wrapping_add(1usize)
                                        }
                                    }
                                };
                                let res: bool = (&pok2)[0usize];
                                if res
                                { (&mut plo)[0usize] = hi }
                                else
                                { (&mut pok1)[0usize] = false }
                            };
                            let res: bool = (&pok1)[0usize];
                            if res
                            {
                                ks1.copy_from_slice(tmp);
                                if n.wrapping_sub(w) <= w
                                { (&mut pdone)[0usize] = true }
                                else
                                { (&mut pw)[0usize] = w.wrapping_add(w) }
                            }
                            else
                            { (&mut pok)[0usize] = false }
                        };
                        let o·1: usize = fill_offsets(b, ks2, oh2);
                        let n1: usize = ks2.len();
                        let mut pw1: [usize; 1] = [1usize; 1usize];
                        let mut pok1: [bool; 1] = [true; 1usize];
                        let mut pdone1: [bool; 1] = [n1 <= 1usize; 1usize];
                        while
                        true
                        {
                            let ok: bool = (&pok1)[0usize];
                            let done: bool = (&pdone1)[0usize];
                            if ! (ok && ! done) { break };
                            let w: usize = (&pw1)[0usize];
                            let n2: usize = ks2.len();
                            let mut plo: [usize; 1] = [0usize; 1usize];
                            let mut pok2: [bool; 1] = [true; 1usize];
                            while
                            true
                            {
                                let ok0: bool = (&pok2)[0usize];
                                let lo: usize = (&plo)[0usize];
                                if ! (ok0 && lo < n2) { break };
                                let lo0: usize = (&plo)[0usize];
                                let mid: usize =
                                    if w <= n2.wrapping_sub(lo0) { lo0.wrapping_add(w) } else { n2 };
                                let hi: usize =
                                    if w <= n2.wrapping_sub(mid) { mid.wrapping_add(w) } else { n2 };
                                let mut pi1: [usize; 1] = [lo0; 1usize];
                                let mut pi2: [usize; 1] = [mid; 1usize];
                                let mut pk: [usize; 1] = [lo0; 1usize];
                                let mut pok3: [bool; 1] = [true; 1usize];
                                while
                                true
                                {
                                    let ok1: bool = (&pok3)[0usize];
                                    let i1: usize = (&pi1)[0usize];
                                    let i2: usize = (&pi2)[0usize];
                                    if ! (ok1 && (i1 != mid || i2 != hi)) { break };
                                    let i10: usize = (&pi1)[0usize];
                                    let i20: usize = (&pi2)[0usize];
                                    let k1: usize = (&pk)[0usize];
                                    if i10 == mid
                                    {
                                        let x1: usize = ks2[i20];
                                        tmp[k1] = x1;
                                        (&mut pi2)[0usize] = i20.wrapping_add(1usize);
                                        (&mut pk)[0usize] = k1.wrapping_add(1usize)
                                    }
                                    else if i20 == hi
                                    {
                                        let x1: usize = ks2[i10];
                                        tmp[k1] = x1;
                                        (&mut pi1)[0usize] = i10.wrapping_add(1usize);
                                        (&mut pk)[0usize] = k1.wrapping_add(1usize)
                                    }
                                    else
                                    {
                                        let x1: usize = ks2[i10];
                                        let x2: usize = ks2[i20];
                                        let c1: i16 = cmp_one(b, rest, x1, x2);
                                        if c1 == 0i16
                                        { (&mut pok3)[0usize] = false }
                                        else if c1 < 0i16
                                        {
                                            tmp[k1] = x1;
                                            (&mut pi1)[0usize] = i10.wrapping_add(1usize);
                                            (&mut pk)[0usize] = k1.wrapping_add(1usize)
                                        }
                                        else
                                        {
                                            tmp[k1] = x2;
                                            (&mut pi2)[0usize] = i20.wrapping_add(1usize);
                                            (&mut pk)[0usize] = k1.wrapping_add(1usize)
                                        }
                                    }
                                };
                                let res: bool = (&pok3)[0usize];
                                if res
                                { (&mut plo)[0usize] = hi }
                                else
                                { (&mut pok2)[0usize] = false }
                            };
                            let res: bool = (&pok2)[0usize];
                            if res
                            {
                                ks2.copy_from_slice(tmp);
                                if n1.wrapping_sub(w) <= w
                                { (&mut pdone1)[0usize] = true }
                                else
                                { (&mut pw1)[0usize] = w.wrapping_add(w) }
                            }
                            else
                            { (&mut pok1)[0usize] = false }
                        };
                        let k1: usize = ks1.len();
                        let mut pi: [usize; 1] = [0usize; 1usize];
                        let mut pr: [i16; 1] = [0i16; 1usize];
                        while
                        true
                        {
                            let i: usize = (&pi)[0usize];
                            let r0: i16 = (&pr)[0usize];
                            if ! (r0 == 0i16 && i < k1) { break };
                            let i0: usize = (&pi)[0usize];
                            let x1: usize = ks1[i0];
                            let x2: usize = ks2[i0];
                            let rk: i16 = cmp_one(b, rest, x1, x2);
                            if rk == 0i16
                            {
                                let v1: usize = jump_raw_data_item(b, x1);
                                let v2: usize = jump_raw_data_item(b, x2);
                                let rv: i16 = cmp_one(b, rest, v1, v2);
                                (&mut pr)[0usize] = rv;
                                (&mut pi)[0usize] = i0.wrapping_add(1usize)
                            }
                            else
                            {
                                (&mut pr)[0usize] = rk;
                                (&mut pi)[0usize] = i0.wrapping_add(1usize)
                            }
                        };
                        let r0: i16 = (&pr)[0usize];
                        let r3: i16 = if r0 == 0i16 { r0 } else { r0 };
                        (&mut po1)[0usize] = o·;
                        (&mut po2)[0usize] = o·1;
                        r3
                    };
                if r0 != 0i16
                {
                    (&mut po1)[0usize] = o1;
                    (&mut po2)[0usize] = o2;
                    (&mut pres)[0usize] = r0
                }
                else
                { (&mut pc)[0usize] = c0.wrapping_sub(1usize) }
            }
            else
            {
                let is_string: bool =
                    mt1 == cbor_major_type_byte_string || mt1 == cbor_major_type_text_string;
                let leaf: usize =
                    if is_string
                    {
                        match h1._2
                        {
                            long_argument::LongArgumentU8 { v } =>
                              raw_uint64 { size: 1u8, value: v as u64 },
                            long_argument::LongArgumentU16 { v } =>
                              raw_uint64 { size: 2u8, value: v as u64 },
                            long_argument::LongArgumentU32 { v } =>
                              raw_uint64 { size: 3u8, value: v as u64 },
                            long_argument::LongArgumentU64 { v } =>
                              raw_uint64 { size: 4u8, value: v },
                            long_argument::LongArgumentOther =>
                              raw_uint64 { size: 0u8, value: h1._1.additional_info as u64 },
                            _ => panic!("Incomplete pattern matching")
                        }.value
                        as
                        usize
                    }
                    else
                    { 0usize };
                let rs: i16 = cmp_leaf(b, is_string, oh1, oh2, leaf);
                if rs != 0i16
                { (&mut pres)[0usize] = rs }
                else
                {
                    let rem: usize = impl_remaining_data_items_header(h1);
                    (&mut po1)[0usize] = oh1.wrapping_add(leaf);
                    (&mut po2)[0usize] = oh2.wrapping_add(leaf);
                    (&mut pc)[0usize] = rem.wrapping_add(c0.wrapping_sub(1usize))
                }
            }
        }
    };
    (&pres)[0usize]
}

pub(crate) fn check_items(
    b: &[u8],
    sc: &mut [usize],
    k0: u64,
    k1: u64,
    hv: &mut [u64],
    idx: &mut [usize],
    o0: usize,
    c0: usize,
    pout: &mut [usize]
) ->
    bool
{
    let mut po: [usize; 1] = [o0; 1usize];
    let mut pc: [usize; 1] = [c0; 1usize];
    let mut pres: [bool; 1] = [true; 1usize];
    while
    true
    {
        let r: bool = (&pres)[0usize];
        let c: usize = (&pc)[0usize];
        if ! (r && c > 0usize) { break };
        let o: usize = (&po)[0usize];
        let c1: usize = (&pc)[0usize];
        let oh: usize = jump_header(b, o);
        let _letpattern: (&[u8], &[u8]) = b.split_at(o);
        let input·: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input23: &[u8] = _letpattern.1;
                let consumed: usize = oh.wrapping_sub(o);
                let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern1.0;
                let _input3: &[u8] = _letpattern1.1;
                input2
            };
        let
        h: dtuple2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument
        =
            read_header(input·);
        let mt: u8 = get_header_major_type(h);
        if mt == cbor_major_type_map
        {
            let k: usize =
                match h._2
                {
                    long_argument::LongArgumentU8 { v } => raw_uint64 { size: 1u8, value: v as u64 },
                    long_argument::LongArgumentU16 { v } =>
                      raw_uint64 { size: 2u8, value: v as u64 },
                    long_argument::LongArgumentU32 { v } =>
                      raw_uint64 { size: 3u8, value: v as u64 },
                    long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                    long_argument::LongArgumentOther =>
                      raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                    _ => panic!("Incomplete pattern matching")
                }.value
                as
                usize;
            let _letpattern1: (&mut [usize], &mut [usize]) = sc.split_at_mut(k);
            let ks: &mut [usize] = _letpattern1.0;
            let r1: &mut [usize] = _letpattern1.1;
            let _letpattern2: (&mut [usize], &mut [usize]) = r1.split_at_mut(k);
            let tmp: &mut [usize] = _letpattern2.0;
            let rest: &mut [usize] = _letpattern2.1;
            let mut pi: [usize; 1] = [0usize; 1usize];
            let mut pe: [usize; 1] = [oh; 1usize];
            let mut pr: [bool; 1] = [true; 1usize];
            while
            true
            {
                let r0: bool = (&pr)[0usize];
                let i: usize = (&pi)[0usize];
                if ! (r0 && i < k) { break };
                let i0: usize = (&pi)[0usize];
                let e: usize = (&pe)[0usize];
                let ok: bool = check_items(b, rest, k0, k1, hv, idx, e, 2usize, pout);
                if ok
                {
                    let o·: usize = pout[0usize];
                    ks[i0] = e;
                    (&mut pi)[0usize] = i0.wrapping_add(1usize);
                    (&mut pe)[0usize] = o·
                }
                else
                { (&mut pr)[0usize] = false }
            };
            let r0: bool = (&pr)[0usize];
            let e: usize = (&pe)[0usize];
            let ok: bool =
                if r0
                {
                    pout[0usize] = e;
                    let k2: usize = ks.len();
                    if k2 <= hv.len() && k2 <= idx.len()
                    {
                        let _letpattern3: (&mut [u64], &mut [u64]) = hv.split_at_mut(k2);
                        let hv1: &mut [u64] = _letpattern3.0;
                        let _hv2: &[u64] = _letpattern3.1;
                        let _letpattern4: (&mut [usize], &mut [usize]) = idx.split_at_mut(k2);
                        let idx1: &mut [usize] = _letpattern4.0;
                        let _idx2: &[usize] = _letpattern4.1;
                        let k3: usize = ks.len();
                        let mut pi1: [usize; 1] = [0usize; 1usize];
                        let mut po1: [usize; 1] = [0usize; 1usize];
                        while
                        true
                        {
                            let i: usize = (&pi1)[0usize];
                            if i >= k3 { break };
                            let i0: usize = (&pi1)[0usize];
                            let x: usize = ks[i0];
                            let sh: sip =
                                hash_items(
                                    b,
                                    k0,
                                    k1,
                                    sip
                                    {
                                        v0: k0 ^ 0x736f6d6570736575u64,
                                        v1: k1 ^ 0x646f72616e646f6du64,
                                        v2: k0 ^ 0x6c7967656e657261u64,
                                        v3: k1 ^ 0x7465646279746573u64,
                                        nw: 0u64
                                    },
                                    x,
                                    1usize,
                                    &mut po1
                                );
                            let h1: u64 = sip_fin(sh);
                            hv1[i0] = h1;
                            idx1[i0] = i0;
                            (&mut pi1)[0usize] = i0.wrapping_add(1usize)
                        };
                        let n: usize = idx1.len();
                        let mut pw: [usize; 1] = [1usize; 1usize];
                        let mut pok: [bool; 1] = [true; 1usize];
                        let mut pdone: [bool; 1] = [n <= 1usize; 1usize];
                        while
                        true
                        {
                            let ok: bool = (&pok)[0usize];
                            let done: bool = (&pdone)[0usize];
                            if ! (ok && ! done) { break };
                            let w: usize = (&pw)[0usize];
                            let n1: usize = idx1.len();
                            let mut plo: [usize; 1] = [0usize; 1usize];
                            let mut pok1: [bool; 1] = [true; 1usize];
                            while
                            true
                            {
                                let ok0: bool = (&pok1)[0usize];
                                let lo: usize = (&plo)[0usize];
                                if ! (ok0 && lo < n1) { break };
                                let lo0: usize = (&plo)[0usize];
                                let mid: usize =
                                    if w <= n1.wrapping_sub(lo0) { lo0.wrapping_add(w) } else { n1 };
                                let hi: usize =
                                    if w <= n1.wrapping_sub(mid) { mid.wrapping_add(w) } else { n1 };
                                let mut pi11: [usize; 1] = [lo0; 1usize];
                                let mut pi2: [usize; 1] = [mid; 1usize];
                                let mut pk: [usize; 1] = [lo0; 1usize];
                                let mut pok2: [bool; 1] = [true; 1usize];
                                while
                                true
                                {
                                    let ok1: bool = (&pok2)[0usize];
                                    let i1: usize = (&pi11)[0usize];
                                    let i2: usize = (&pi2)[0usize];
                                    if ! (ok1 && (i1 != mid || i2 != hi)) { break };
                                    let i10: usize = (&pi11)[0usize];
                                    let i20: usize = (&pi2)[0usize];
                                    let k4: usize = (&pk)[0usize];
                                    if i10 == mid
                                    {
                                        let x: usize = idx1[i20];
                                        tmp[k4] = x;
                                        (&mut pi2)[0usize] = i20.wrapping_add(1usize);
                                        (&mut pk)[0usize] = k4.wrapping_add(1usize)
                                    }
                                    else if i20 == hi
                                    {
                                        let x: usize = idx1[i10];
                                        tmp[k4] = x;
                                        (&mut pi11)[0usize] = i10.wrapping_add(1usize);
                                        (&mut pk)[0usize] = k4.wrapping_add(1usize)
                                    }
                                    else
                                    {
                                        let x1: usize = idx1[i10];
                                        let x2: usize = idx1[i20];
                                        let hi1: u64 = hv1[x1];
                                        let hj: u64 = hv1[x2];
                                        let c10: i16 =
                                            if hi1 < hj
                                            { -1i16 }
                                            else if hj < hi1
                                            { 1i16 }
                                            else
                                            {
                                                let xi: usize = ks[x1];
                                                let xj: usize = ks[x2];
                                                cmp_one(b, rest, xi, xj)
                                            };
                                        if c10 == 0i16
                                        { (&mut pok2)[0usize] = false }
                                        else if c10 < 0i16
                                        {
                                            tmp[k4] = x1;
                                            (&mut pi11)[0usize] = i10.wrapping_add(1usize);
                                            (&mut pk)[0usize] = k4.wrapping_add(1usize)
                                        }
                                        else
                                        {
                                            tmp[k4] = x2;
                                            (&mut pi2)[0usize] = i20.wrapping_add(1usize);
                                            (&mut pk)[0usize] = k4.wrapping_add(1usize)
                                        }
                                    }
                                };
                                let res: bool = (&pok2)[0usize];
                                if res
                                { (&mut plo)[0usize] = hi }
                                else
                                { (&mut pok1)[0usize] = false }
                            };
                            let res: bool = (&pok1)[0usize];
                            if res
                            {
                                idx1.copy_from_slice(tmp);
                                if n.wrapping_sub(w) <= w
                                { (&mut pdone)[0usize] = true }
                                else
                                { (&mut pw)[0usize] = w.wrapping_add(w) }
                            }
                            else
                            { (&mut pok)[0usize] = false }
                        };
                        (&pok)[0usize]
                    }
                    else
                    {
                        let n: usize = ks.len();
                        let mut pw: [usize; 1] = [1usize; 1usize];
                        let mut pok: [bool; 1] = [true; 1usize];
                        let mut pdone: [bool; 1] = [n <= 1usize; 1usize];
                        while
                        true
                        {
                            let ok: bool = (&pok)[0usize];
                            let done: bool = (&pdone)[0usize];
                            if ! (ok && ! done) { break };
                            let w: usize = (&pw)[0usize];
                            let n1: usize = ks.len();
                            let mut plo: [usize; 1] = [0usize; 1usize];
                            let mut pok1: [bool; 1] = [true; 1usize];
                            while
                            true
                            {
                                let ok0: bool = (&pok1)[0usize];
                                let lo: usize = (&plo)[0usize];
                                if ! (ok0 && lo < n1) { break };
                                let lo0: usize = (&plo)[0usize];
                                let mid: usize =
                                    if w <= n1.wrapping_sub(lo0) { lo0.wrapping_add(w) } else { n1 };
                                let hi: usize =
                                    if w <= n1.wrapping_sub(mid) { mid.wrapping_add(w) } else { n1 };
                                let mut pi1: [usize; 1] = [lo0; 1usize];
                                let mut pi2: [usize; 1] = [mid; 1usize];
                                let mut pk: [usize; 1] = [lo0; 1usize];
                                let mut pok2: [bool; 1] = [true; 1usize];
                                while
                                true
                                {
                                    let ok1: bool = (&pok2)[0usize];
                                    let i1: usize = (&pi1)[0usize];
                                    let i2: usize = (&pi2)[0usize];
                                    if ! (ok1 && (i1 != mid || i2 != hi)) { break };
                                    let i10: usize = (&pi1)[0usize];
                                    let i20: usize = (&pi2)[0usize];
                                    let k3: usize = (&pk)[0usize];
                                    if i10 == mid
                                    {
                                        let x: usize = ks[i20];
                                        tmp[k3] = x;
                                        (&mut pi2)[0usize] = i20.wrapping_add(1usize);
                                        (&mut pk)[0usize] = k3.wrapping_add(1usize)
                                    }
                                    else if i20 == hi
                                    {
                                        let x: usize = ks[i10];
                                        tmp[k3] = x;
                                        (&mut pi1)[0usize] = i10.wrapping_add(1usize);
                                        (&mut pk)[0usize] = k3.wrapping_add(1usize)
                                    }
                                    else
                                    {
                                        let x1: usize = ks[i10];
                                        let x2: usize = ks[i20];
                                        let c10: i16 = cmp_one(b, rest, x1, x2);
                                        if c10 == 0i16
                                        { (&mut pok2)[0usize] = false }
                                        else if c10 < 0i16
                                        {
                                            tmp[k3] = x1;
                                            (&mut pi1)[0usize] = i10.wrapping_add(1usize);
                                            (&mut pk)[0usize] = k3.wrapping_add(1usize)
                                        }
                                        else
                                        {
                                            tmp[k3] = x2;
                                            (&mut pi2)[0usize] = i20.wrapping_add(1usize);
                                            (&mut pk)[0usize] = k3.wrapping_add(1usize)
                                        }
                                    }
                                };
                                let res: bool = (&pok2)[0usize];
                                if res
                                { (&mut plo)[0usize] = hi }
                                else
                                { (&mut pok1)[0usize] = false }
                            };
                            let res: bool = (&pok1)[0usize];
                            if res
                            {
                                ks.copy_from_slice(tmp);
                                if n.wrapping_sub(w) <= w
                                { (&mut pdone)[0usize] = true }
                                else
                                { (&mut pw)[0usize] = w.wrapping_add(w) }
                            }
                            else
                            { (&mut pok)[0usize] = false }
                        };
                        let ok: bool = (&pok)[0usize];
                        if ok { ok } else { ok }
                    }
                }
                else
                { false };
            if ok
            {
                let o·: usize = pout[0usize];
                (&mut po)[0usize] = o·;
                (&mut pc)[0usize] = c1.wrapping_sub(1usize)
            }
            else
            { (&mut pres)[0usize] = false }
        }
        else
        {
            let is_string: bool =
                mt == cbor_major_type_byte_string || mt == cbor_major_type_text_string;
            let leaf: usize =
                if is_string
                {
                    match h._2
                    {
                        long_argument::LongArgumentU8 { v } =>
                          raw_uint64 { size: 1u8, value: v as u64 },
                        long_argument::LongArgumentU16 { v } =>
                          raw_uint64 { size: 2u8, value: v as u64 },
                        long_argument::LongArgumentU32 { v } =>
                          raw_uint64 { size: 3u8, value: v as u64 },
                        long_argument::LongArgumentU64 { v } => raw_uint64 { size: 4u8, value: v },
                        long_argument::LongArgumentOther =>
                          raw_uint64 { size: 0u8, value: h._1.additional_info as u64 },
                        _ => panic!("Incomplete pattern matching")
                    }.value
                    as
                    usize
                }
                else
                { 0usize };
            let rem: usize = impl_remaining_data_items_header(h);
            (&mut po)[0usize] = oh.wrapping_add(leaf);
            (&mut pc)[0usize] = rem.wrapping_add(c1.wrapping_sub(1usize))
        }
    };
    let r: bool = (&pres)[0usize];
    if r
    {
        let o: usize = (&po)[0usize];
        pout[0usize] = o;
        r
    }
    else
    { r }
}

fn dupcheck_sort_scratch_ok(
    map_depth_bound: usize,
    map_length_bound: usize,
    scratch_len: usize
) ->
    bool
{
    map_depth_bound == 0usize
    ||
    map_length_bound <= scratch_len.wrapping_div(3usize).wrapping_div(map_depth_bound)
}

fn check_dups_top_gen(
    b: &[u8],
    sc: &mut [usize],
    k0: u64,
    k1: u64,
    hv: &mut [u64],
    idx: &mut [usize]
) ->
    bool
{
    let mut pout: [usize; 1] = [0usize; 1usize];
    check_items(b, sc, k0, k1, hv, idx, 0usize, 1usize, &mut pout)
}

fn check_dups_top(b: &[u8], sc: &mut [usize]) -> bool
{
    let _letpattern: (&mut [usize], &mut [usize]) = sc.split_at_mut(0usize);
    let idx: &mut [usize] = _letpattern.0;
    let sc·: &mut [usize] = _letpattern.1;
    let mut a: [u64; 1] = [0u64; 1usize];
    let hv: &mut [u64] = &mut a;
    check_dups_top_gen(b, sc·, 0u64, 0u64, hv, idx)
}

fn dupcheck_hash_scratch_ok(
    map_depth_bound: usize,
    map_length_bound: usize,
    scratch_len: usize,
    hash_scratch_len: usize
) ->
    bool
{
    if map_length_bound <= scratch_len && map_length_bound <= hash_scratch_len
    {
        dupcheck_sort_scratch_ok(
            map_depth_bound,
            map_length_bound,
            scratch_len.wrapping_sub(map_length_bound)
        )
    }
    else
    { false }
}

fn check_dups_top_hash(b: &[u8], n: usize, k0: u64, k1: u64, sc: &mut [usize], hv: &mut [u64]) ->
    bool
{
    let _letpattern: (&mut [usize], &mut [usize]) = sc.split_at_mut(n);
    let idx: &mut [usize] = _letpattern.0;
    let sc·: &mut [usize] = _letpattern.1;
    check_dups_top_gen(b, sc·, k0, k1, hv, idx)
}

fn cbor_validate_nondet(map_key_bound: option__size_t, strict_check: bool, input: &[u8]) ->
    usize
{
    let mut poff: [usize; 1] = [0usize; 1usize];
    let res: bool = validate_raw_data_item(input, &mut poff);
    if res
    {
        let off: usize = (&poff)[0usize];
        let _letpattern: (&[u8], &[u8]) = input.split_at(0usize);
        let input·: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input23: &[u8] = _letpattern.1;
                let consumed: usize = off.wrapping_sub(0usize);
                let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern1.0;
                let _input3: &[u8] = _letpattern1.1;
                input2
            };
        let res1: bool = impl_check_valid_basic(map_key_bound, strict_check, input·);
        if res1 { off } else { 0usize }
    }
    else
    { 0usize }
}

fn cbor_validate_nondet_map_length_bounded(
    map_length_bound: usize,
    map_key_bound: option__size_t,
    strict_check: bool,
    input: &[u8]
) ->
    usize
{
    let mut poff: [usize; 1] = [0usize; 1usize];
    let res: bool = validate_raw_data_item_map_length_bounded(map_length_bound, input, &mut poff);
    if res
    {
        let off: usize = (&poff)[0usize];
        let _letpattern: (&[u8], &[u8]) = input.split_at(0usize);
        let input·: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input23: &[u8] = _letpattern.1;
                let consumed: usize = off.wrapping_sub(0usize);
                let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern1.0;
                let _input3: &[u8] = _letpattern1.1;
                input2
            };
        let res1: bool = impl_check_valid_basic(map_key_bound, strict_check, input·);
        if res1 { off } else { 0usize }
    }
    else
    { 0usize }
}

fn cbor_validate_nondet_bounded(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: option__size_t,
    input: &[u8]
) ->
    usize
{
    let mut poff: [usize; 1] = [0usize; 1usize];
    let res: bool =
        validate_raw_data_item_bounded(
            map_depth_bound,
            map_length_bound,
            map_key_bound,
            input,
            &mut poff
        );
    if res
    {
        let off: usize = (&poff)[0usize];
        let _letpattern: (&[u8], &[u8]) = input.split_at(0usize);
        let input·: &[u8] =
            {
                let _input1: &[u8] = _letpattern.0;
                let input23: &[u8] = _letpattern.1;
                let consumed: usize = off.wrapping_sub(0usize);
                let _letpattern1: (&[u8], &[u8]) = input23.split_at(consumed);
                let input2: &[u8] = _letpattern1.0;
                let _input3: &[u8] = _letpattern1.1;
                input2
            };
        let res1: bool = impl_check_valid_basic(option__size_t::None, false, input·);
        if res1 { off } else { 0usize }
    }
    else
    { 0usize }
}

fn cbor_validate_nondet_bounded_sort_scratch_ok_impl(
    map_depth_bound: usize,
    map_length_bound: usize,
    scratch_len: usize
) ->
    bool
{ dupcheck_sort_scratch_ok(map_depth_bound, map_length_bound, scratch_len) }

fn cbor_validate_nondet_bounded_sort(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: option__size_t,
    input: &[u8],
    scratch: &mut [usize]
) ->
    usize
{
    if ! dupcheck_sort_scratch_ok(map_depth_bound, map_length_bound, scratch.len())
    { 0usize }
    else
    {
        let mut poff: [usize; 1] = [0usize; 1usize];
        let res: bool =
            validate_raw_data_item_bounded(
                map_depth_bound,
                map_length_bound,
                map_key_bound,
                input,
                &mut poff
            );
        if res
        {
            let off: usize = (&poff)[0usize];
            let ok: bool = check_dups_top(input, scratch);
            if ok { off } else { 0usize }
        }
        else
        { 0usize }
    }
}

fn cbor_validate_nondet_bounded_hash_scratch_ok_impl(
    map_depth_bound: usize,
    map_length_bound: usize,
    scratch_len: usize,
    hash_scratch_len: usize
) ->
    bool
{ dupcheck_hash_scratch_ok(map_depth_bound, map_length_bound, scratch_len, hash_scratch_len) }

fn cbor_validate_nondet_bounded_hash(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: option__size_t,
    k0: u64,
    k1: u64,
    input: &[u8],
    scratch: &mut [usize],
    hash_scratch: &mut [u64]
) ->
    usize
{
    if
    !
    dupcheck_hash_scratch_ok(map_depth_bound, map_length_bound, scratch.len(), hash_scratch.len())
    { 0usize }
    else
    {
        let mut poff: [usize; 1] = [0usize; 1usize];
        let res: bool =
            validate_raw_data_item_bounded(
                map_depth_bound,
                map_length_bound,
                map_key_bound,
                input,
                &mut poff
            );
        if res
        {
            let off: usize = (&poff)[0usize];
            let ok: bool =
                check_dups_top_hash(input, map_length_bound, k0, k1, scratch, hash_scratch);
            if ok { off } else { 0usize }
        }
        else
        { 0usize }
    }
}

pub(crate) fn cbor_raw_reset_perm_tot <'a>(c: cbor_raw <'a>) -> cbor_raw <'a> { c }

fn cbor_nondet_validate(map_key_bound: option__size_t, strict_check: bool, input: &[u8]) ->
    usize
{ cbor_validate_nondet(map_key_bound, strict_check, input) }

pub(crate) fn cbor_nondet_parse_valid <'a>(input: &'a [u8], len: usize) -> cbor_raw <'a>
{ cbor_parse(input, len) }

#[derive(PartialEq, Clone, Copy)]
pub enum option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t· <'a>
{
    None,
    Some { v: (cbor_raw <'a>, &'a [u8]) }
}

pub(crate) fn cbor_nondet_parse <'a>(
    map_key_bound: option__size_t,
    strict_check: bool,
    input: &'a [u8]
) ->
    option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·
    <'a>
{
    let len: usize = cbor_nondet_validate(map_key_bound, strict_check, input);
    if len == 0usize
    { option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None }
    else
    {
        let _letpattern: (&[u8], &[u8]) = input.split_at(len);
        let inl: &[u8] = _letpattern.0;
        let inr: &[u8] = _letpattern.1;
        let resl: cbor_raw = cbor_nondet_parse_valid(inl, len);
        option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some
        { v: (resl,inr) }
    }
}

fn cbor_nondet_validate_map_length_bounded(
    map_length_bound: usize,
    map_key_bound: option__size_t,
    strict_check: bool,
    input: &[u8]
) ->
    usize
{
    cbor_validate_nondet_map_length_bounded(map_length_bound, map_key_bound, strict_check, input)
}

pub(crate) fn cbor_nondet_parse_map_length_bounded <'a>(
    map_length_bound: usize,
    map_key_bound: option__size_t,
    strict_check: bool,
    input: &'a [u8]
) ->
    option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·
    <'a>
{
    let len: usize =
        cbor_nondet_validate_map_length_bounded(
            map_length_bound,
            map_key_bound,
            strict_check,
            input
        );
    if len == 0usize
    { option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None }
    else
    {
        let _letpattern: (&[u8], &[u8]) = input.split_at(len);
        let inl: &[u8] = _letpattern.0;
        let inr: &[u8] = _letpattern.1;
        let resl: cbor_raw = cbor_nondet_parse_valid(inl, len);
        option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some
        { v: (resl,inr) }
    }
}

fn cbor_nondet_validate_bounded(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: option__size_t,
    input: &[u8]
) ->
    usize
{ cbor_validate_nondet_bounded(map_depth_bound, map_length_bound, map_key_bound, input) }

pub(crate) fn cbor_nondet_parse_bounded <'a>(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: option__size_t,
    input: &'a [u8]
) ->
    option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·
    <'a>
{
    let len: usize =
        cbor_nondet_validate_bounded(map_depth_bound, map_length_bound, map_key_bound, input);
    if len == 0usize
    { option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::None }
    else
    {
        let _letpattern: (&[u8], &[u8]) = input.split_at(len);
        let inl: &[u8] = _letpattern.0;
        let inr: &[u8] = _letpattern.1;
        let resl: cbor_raw = cbor_nondet_parse_valid(inl, len);
        option__·CBOR_Pulse_Raw_Type_cbor_raw···Pulse_Lib_Slice_slice·uint8_t·::Some
        { v: (resl,inr) }
    }
}

pub(crate) fn cbor_nondet_bounded_sort_scratch_ok_impl(
    map_depth_bound: usize,
    map_length_bound: usize,
    scratch_len: usize
) ->
    bool
{
    cbor_validate_nondet_bounded_sort_scratch_ok_impl(
        map_depth_bound,
        map_length_bound,
        scratch_len
    )
}

pub(crate) fn cbor_nondet_validate_bounded_sort(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: option__size_t,
    scratch: &mut [usize],
    input: &[u8]
) ->
    usize
{
    cbor_validate_nondet_bounded_sort(
        map_depth_bound,
        map_length_bound,
        map_key_bound,
        input,
        scratch
    )
}

pub(crate) fn cbor_nondet_bounded_hash_scratch_ok_impl(
    map_depth_bound: usize,
    map_length_bound: usize,
    scratch_len: usize,
    hash_scratch_len: usize
) ->
    bool
{
    cbor_validate_nondet_bounded_hash_scratch_ok_impl(
        map_depth_bound,
        map_length_bound,
        scratch_len,
        hash_scratch_len
    )
}

pub(crate) fn cbor_nondet_validate_bounded_hash(
    map_depth_bound: usize,
    map_length_bound: usize,
    map_key_bound: option__size_t,
    k0: u64,
    k1: u64,
    scratch: &mut [usize],
    hash_scratch: &mut [u64],
    input: &[u8]
) ->
    usize
{
    cbor_validate_nondet_bounded_hash(
        map_depth_bound,
        map_length_bound,
        map_key_bound,
        k0,
        k1,
        input,
        scratch,
        hash_scratch
    )
}

pub(crate) fn cbor_nondet_size(x: cbor_raw, bound: usize) -> usize { cbor_size(x, bound) }

pub(crate) fn cbor_nondet_serialize(x: cbor_raw, output: &mut [u8]) -> option__size_t
{
    let len: usize = cbor_size(x, output.len());
    if len == 0usize
    { option__size_t::None }
    else
    {
        let _letpattern: (&mut [u8], &mut [u8]) = output.split_at_mut(len);
        let out: &mut [u8] = _letpattern.0;
        let _outr: &[u8] = _letpattern.1;
        let res: usize = cbor_serialize(x, out);
        option__size_t::Some { v: res }
    }
}

pub(crate) fn cbor_nondet_mk_simple_value <'a>(v: u8) -> cbor_raw <'a>
{ cbor_raw::CBOR_Case_Simple { v } }

fn cbor_nondet_mk_int64_gen <'a>(ty: u8, v: u64) -> cbor_raw <'a>
{
    let resi: cbor_int =
        cbor_int
        {
            cbor_int_type: ty,
            cbor_int_size: (mk_raw_uint64(v)).size,
            cbor_int_value: (mk_raw_uint64(v)).value
        };
    cbor_raw::CBOR_Case_Int { v: resi }
}

pub(crate) fn cbor_nondet_mk_uint64 <'a>(v: u64) -> cbor_raw <'a>
{ cbor_nondet_mk_int64_gen(cbor_major_type_uint64, v) }

pub(crate) fn cbor_nondet_mk_neg_int64 <'a>(v: u64) -> cbor_raw <'a>
{ cbor_nondet_mk_int64_gen(cbor_major_type_neg_int64, v) }

pub(crate) fn cbor_nondet_mk_string <'a>(ty: u8, s: &'a [u8]) -> cbor_raw <'a>
{
    let len64: raw_uint64 = mk_raw_uint64(s.len() as u64);
    let ress: cbor_string =
        cbor_string { cbor_string_type: ty, cbor_string_size: len64.size, cbor_string_ptr: s };
    let res1: cbor_raw = cbor_raw::CBOR_Case_String { v: ress };
    cbor_raw_reset_perm_tot(res1)
}

pub(crate) fn cbor_nondet_mk_tagged <'a>(tag: u64, r: &'a [cbor_raw <'a>]) -> cbor_raw <'a>
{
    let tag64: raw_uint64 = mk_raw_uint64(tag);
    let res·: cbor_tagged = cbor_tagged { cbor_tagged_tag: tag64, cbor_tagged_ptr: r };
    let res1: cbor_raw = cbor_raw::CBOR_Case_Tagged { v: res· };
    cbor_raw_reset_perm_tot(res1)
}

pub(crate) fn cbor_nondet_mk_map_entry <'a>(xk: cbor_raw <'a>, xv: cbor_raw <'a>) ->
    cbor_map_entry
    <'a>
{
    let xk·: cbor_raw = cbor_raw_reset_perm_tot(xk);
    let xv·: cbor_raw = cbor_raw_reset_perm_tot(xv);
    cbor_map_entry { cbor_map_entry_key: xk·, cbor_map_entry_value: xv· }
}

pub(crate) fn cbor_nondet_mk_array <'a>(a: &'a [cbor_raw <'a>]) -> cbor_raw <'a>
{
    let len64: raw_uint64 = mk_raw_uint64(a.len() as u64);
    let res·: cbor_array = cbor_array { cbor_array_length_size: len64.size, cbor_array_ptr: a };
    let res1: cbor_raw = cbor_raw::CBOR_Case_Array { v: res· };
    cbor_raw_reset_perm_tot(res1)
}

#[derive(PartialEq, Clone, Copy)]
pub enum option__CBOR_Pulse_Raw_Type_cbor_raw <'a>
{
    None,
    Some { v: cbor_raw <'a> }
}

pub(crate) fn cbor_nondet_mk_map <'a>(a: &'a [cbor_map_entry <'a>]) ->
    option__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    let mut dest: [cbor_raw; 1] = [cbor_raw::CBOR_Case_Simple { v: 0u8 }; 1usize];
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
            let correct: bool = cbor_nondet_no_setoid_repeats(a);
            if correct
            {
                let raw_len: raw_uint64 = mk_raw_uint64(a.len() as u64);
                let res·: cbor_map =
                    cbor_map { cbor_map_length_size: raw_len.size, cbor_map_ptr: a };
                let res1: cbor_raw = cbor_raw::CBOR_Case_Map { v: res· };
                let res: cbor_raw = cbor_raw_reset_perm_tot(res1);
                (&mut dest)[0usize] = res;
                true
            }
            else
            { false }
        };
    if bres
    {
        let res: cbor_raw = (&dest)[0usize];
        option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: res }
    }
    else
    { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
}

pub(crate) fn cbor_nondet_equal(x1: cbor_raw, x2: cbor_raw) -> bool
{ cbor_nondet_equiv(x1, x2) }

pub(crate) fn cbor_nondet_major_type(x: cbor_raw) -> u8 { impl_major_type(x) }

pub(crate) fn cbor_nondet_read_uint64(x: cbor_raw) -> u64
{
    let res: raw_uint64 =
        match x
        {
            cbor_raw::CBOR_Case_Int { v: c· } =>
              raw_uint64 { size: c·.cbor_int_size, value: c·.cbor_int_value },
            _ => panic!("Incomplete pattern matching")
        };
    res.value
}

pub(crate) fn cbor_nondet_get_string <'a>(x: cbor_raw <'a>) -> &'a [u8]
{
    match x
    {
        cbor_raw::CBOR_Case_String { v: c· } => c·.cbor_string_ptr,
        _ => panic!("Incomplete pattern matching")
    }
}

pub(crate) fn cbor_nondet_get_tagged_tag(x: cbor_raw) -> u64
{
    let res: raw_uint64 =
        match x
        {
            cbor_raw::CBOR_Case_Tagged { v: c· } => c·.cbor_tagged_tag,
            cbor_raw::CBOR_Case_Serialized_Tagged { v: c· } => c·.cbor_serialized_header,
            _ => panic!("Incomplete pattern matching")
        };
    res.value
}

pub(crate) fn cbor_nondet_get_tagged_payload <'a>(x: cbor_raw <'a>) -> cbor_raw <'a>
{ cbor_match_tagged_get_payload(x) }

pub(crate) fn cbor_nondet_read_simple_value(x: cbor_raw) -> u8
{
    match x
    { cbor_raw::CBOR_Case_Simple { v: res } => res, _ => panic!("Incomplete pattern matching") }
}

pub(crate) fn cbor_nondet_get_array_length(x: cbor_raw) -> u64
{
    let res: raw_uint64 =
        match x
        {
            cbor_raw::CBOR_Case_Array { v: c· } =>
              raw_uint64
              { size: c·.cbor_array_length_size, value: (c·.cbor_array_ptr).len() as u64 },
            cbor_raw::CBOR_Case_Serialized_Array { v: c· } => c·.cbor_serialized_header,
            _ => panic!("Incomplete pattern matching")
        };
    res.value
}

pub(crate) fn cbor_nondet_array_iterator_start <'a>(x: cbor_raw <'a>) ->
    cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{ cbor_array_iterator_init(x) }

pub(crate) fn cbor_nondet_array_iterator_is_empty(
    x: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
) ->
    bool
{ cbor_array_iterator_is_empty(x) }

pub(crate) fn cbor_nondet_array_iterator_next <'b, 'a>(
    x: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>]
) ->
    cbor_raw
    <'a>
{ cbor_array_iterator_next(x) }

pub(crate) fn cbor_nondet_get_array_item <'a>(x: cbor_raw <'a>, i: u64) -> cbor_raw <'a>
{ cbor_array_item(x, i) }

pub(crate) fn cbor_nondet_get_map_length(x: cbor_raw) -> u64
{
    let res: raw_uint64 =
        match x
        {
            cbor_raw::CBOR_Case_Map { v: c· } =>
              raw_uint64 { size: c·.cbor_map_length_size, value: (c·.cbor_map_ptr).len() as u64 },
            cbor_raw::CBOR_Case_Serialized_Map { v: c· } => c·.cbor_serialized_header,
            _ => panic!("Incomplete pattern matching")
        };
    res.value
}

pub(crate) fn cbor_nondet_map_iterator_start <'a>(x: cbor_raw <'a>) ->
    cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
    <'a>
{ cbor_map_iterator_init(x) }

pub(crate) fn cbor_nondet_map_iterator_is_empty(
    x: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
) ->
    bool
{ cbor_map_iterator_is_empty(x) }

pub(crate) fn cbor_nondet_map_iterator_next <'b, 'a>(
    x: &'b mut [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>]
) ->
    cbor_map_entry
    <'a>
{ cbor_map_iterator_next(x) }

pub(crate) fn cbor_nondet_map_entry_key <'a>(x2: cbor_map_entry <'a>) -> cbor_raw <'a>
{ x2.cbor_map_entry_key }

pub(crate) fn cbor_nondet_map_entry_value <'a>(x2: cbor_map_entry <'a>) -> cbor_raw <'a>
{ x2.cbor_map_entry_value }

pub(crate) fn cbor_nondet_map_get <'a>(x: cbor_raw <'a>, k: cbor_raw <'a>) ->
    option__CBOR_Pulse_Raw_Type_cbor_raw
    <'a>
{
    let mut dest: [cbor_raw; 1] = [k; 1usize];
    let i: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry =
        cbor_nondet_map_iterator_start(x);
    let mut pi: [cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry; 1] = [i; 1usize];
    let mut pres: [bool; 1] = [false; 1usize];
    let __anf0: bool = cbor_nondet_map_iterator_is_empty(i);
    let cont: bool = ! __anf0;
    let mut pcont: [bool; 1] = [cont; 1usize];
    while
    true
    {
        let res: bool = (&pres)[0usize];
        let cont1: bool = (&pcont)[0usize];
        if ! (cont1 && ! res) { break };
        let y: cbor_map_entry = cbor_nondet_map_iterator_next(&mut pi);
        let __anf01: bool = cbor_nondet_equal(y.cbor_map_entry_key, k);
        if __anf01
        {
            (&mut dest)[0usize] = y.cbor_map_entry_value;
            (&mut pres)[0usize] = true
        }
        else
        {
            let i1: cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry = (&pi)[0usize];
            let __anf02: bool = cbor_nondet_map_iterator_is_empty(i1);
            let cont10: bool = ! __anf02;
            (&mut pcont)[0usize] = cont10
        }
    };
    let bres: bool = (&pres)[0usize];
    if bres
    {
        let res: cbor_raw = (&dest)[0usize];
        option__CBOR_Pulse_Raw_Type_cbor_raw::Some { v: res }
    }
    else
    { option__CBOR_Pulse_Raw_Type_cbor_raw::None }
}

pub type major_type_t = u8;

pub type major_type_uint64_or_neg_int64 = u8;

pub type simple_value = u8;

pub type major_type_byte_string_or_text_string = u8;

pub const cbor_major_type_simple_value: u8 = 7u8;

pub const min_simple_value_long_argument: u8 = 32u8;

pub const cbor_major_type_byte_string: u8 = 2u8;

pub const cbor_major_type_text_string: u8 = 3u8;

pub const cbor_major_type_array: u8 = 4u8;

pub const cbor_major_type_map: u8 = 5u8;

pub const cbor_major_type_tagged: u8 = 6u8;

pub const cbor_major_type_uint64: u8 = 0u8;

pub const cbor_major_type_neg_int64: u8 = 1u8;

pub const max_simple_value_additional_info: u8 = 23u8;

pub type cbor_array_iterator <'a> = cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>;

pub type cbor_map_iterator <'a> = cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>;

pub type cbor_nondet_t <'a> = cbor_raw <'a>;

pub type cbor_nondet_array_iterator_t <'a> =
cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw <'a>;

pub type cbor_nondet_map_iterator_t <'a> =
cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry <'a>;

pub type cbor_nondet_map_entry_t <'a> = cbor_map_entry <'a>;
