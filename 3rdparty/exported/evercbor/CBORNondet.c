

#include "internal/CBORNondet.h"

static uint8_t LowParse_BitFields_get_bitfield_gen8(uint8_t x, uint32_t lo, uint32_t hi)
{
  return ((uint32_t)x << 8U - hi & 0xFFU) >> 8U - hi + lo;
}

static uint8_t
LowParse_BitFields_set_bitfield_gen8(uint8_t x, uint32_t lo, uint32_t hi, uint8_t v)
{
  return (uint32_t)x & (uint32_t)~(255U >> 8U - (hi - lo) << lo) | (uint32_t)v << lo;
}

#define CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS (24U)

#define CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_UNASSIGNED_MIN (28U)

typedef struct CBOR_Spec_Raw_EverParse_initial_byte_t_s
{
  uint8_t major_type;
  uint8_t additional_info;
}
CBOR_Spec_Raw_EverParse_initial_byte_t;

#define CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_16_BITS (25U)

#define CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_32_BITS (26U)

#define CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_64_BITS (27U)

#define CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue 0
#define CBOR_Spec_Raw_EverParse_LongArgumentU8 1
#define CBOR_Spec_Raw_EverParse_LongArgumentU16 2
#define CBOR_Spec_Raw_EverParse_LongArgumentU32 3
#define CBOR_Spec_Raw_EverParse_LongArgumentU64 4
#define CBOR_Spec_Raw_EverParse_LongArgumentOther 5

typedef uint8_t CBOR_Spec_Raw_EverParse_long_argument_tags;

typedef struct CBOR_Spec_Raw_EverParse_long_argument_s
{
  CBOR_Spec_Raw_EverParse_long_argument_tags tag;
  union {
    uint8_t case_LongArgumentSimpleValue;
    uint8_t case_LongArgumentU8;
    uint16_t case_LongArgumentU16;
    uint32_t case_LongArgumentU32;
    uint64_t case_LongArgumentU64;
  }
  ;
}
CBOR_Spec_Raw_EverParse_long_argument;

typedef struct CBOR_Spec_Raw_EverParse_header_s
{
  CBOR_Spec_Raw_EverParse_initial_byte_t fst;
  CBOR_Spec_Raw_EverParse_long_argument snd;
}
CBOR_Spec_Raw_EverParse_header;

static uint64_t
CBOR_Spec_Raw_EverParse_argument_as_uint64(
  CBOR_Spec_Raw_EverParse_initial_byte_t b,
  CBOR_Spec_Raw_EverParse_long_argument x
)
{
  CBOR_Spec_Raw_Base_raw_uint64 ite;
  if (x.tag == CBOR_Spec_Raw_EverParse_LongArgumentU8)
    ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 1U, .value = (uint64_t)x.case_LongArgumentU8 });
  else if (x.tag == CBOR_Spec_Raw_EverParse_LongArgumentU16)
    ite =
      ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 2U, .value = (uint64_t)x.case_LongArgumentU16 });
  else if (x.tag == CBOR_Spec_Raw_EverParse_LongArgumentU32)
    ite =
      ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 3U, .value = (uint64_t)x.case_LongArgumentU32 });
  else if (x.tag == CBOR_Spec_Raw_EverParse_LongArgumentU64)
    ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 4U, .value = x.case_LongArgumentU64 });
  else if (x.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
    ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 0U, .value = (uint64_t)b.additional_info });
  else
    ite =
      KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
        "unreachable (pattern matches are exhaustive in F*)");
  return ite.value;
}

static CBOR_Spec_Raw_EverParse_header
CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(uint8_t t, CBOR_Spec_Raw_Base_raw_uint64 x)
{
  if (x.size == 0U)
    return
      (
        (CBOR_Spec_Raw_EverParse_header){
          .fst = { .major_type = t, .additional_info = (uint8_t)x.value },
          .snd = { .tag = CBOR_Spec_Raw_EverParse_LongArgumentOther }
        }
      );
  else if (x.size == 1U)
    return
      (
        (CBOR_Spec_Raw_EverParse_header){
          .fst = {
            .major_type = t,
            .additional_info = CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS
          },
          .snd = {
            .tag = CBOR_Spec_Raw_EverParse_LongArgumentU8,
            { .case_LongArgumentU8 = (uint8_t)x.value }
          }
        }
      );
  else if (x.size == 2U)
    return
      (
        (CBOR_Spec_Raw_EverParse_header){
          .fst = {
            .major_type = t,
            .additional_info = CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_16_BITS
          },
          .snd = {
            .tag = CBOR_Spec_Raw_EverParse_LongArgumentU16,
            { .case_LongArgumentU16 = (uint16_t)x.value }
          }
        }
      );
  else if (x.size == 3U)
    return
      (
        (CBOR_Spec_Raw_EverParse_header){
          .fst = {
            .major_type = t,
            .additional_info = CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_32_BITS
          },
          .snd = {
            .tag = CBOR_Spec_Raw_EverParse_LongArgumentU32,
            { .case_LongArgumentU32 = (uint32_t)x.value }
          }
        }
      );
  else
    return
      (
        (CBOR_Spec_Raw_EverParse_header){
          .fst = {
            .major_type = t,
            .additional_info = CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_64_BITS
          },
          .snd = {
            .tag = CBOR_Spec_Raw_EverParse_LongArgumentU64,
            { .case_LongArgumentU64 = x.value }
          }
        }
      );
}

static CBOR_Spec_Raw_EverParse_header
CBOR_Spec_Raw_EverParse_simple_value_as_argument(uint8_t x)
{
  if (x <= MAX_SIMPLE_VALUE_ADDITIONAL_INFO)
    return
      (
        (CBOR_Spec_Raw_EverParse_header){
          .fst = { .major_type = CBOR_MAJOR_TYPE_SIMPLE_VALUE, .additional_info = x },
          .snd = { .tag = CBOR_Spec_Raw_EverParse_LongArgumentOther }
        }
      );
  else
    return
      (
        (CBOR_Spec_Raw_EverParse_header){
          .fst = {
            .major_type = CBOR_MAJOR_TYPE_SIMPLE_VALUE,
            .additional_info = CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS
          },
          .snd = {
            .tag = CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue,
            { .case_LongArgumentSimpleValue = x }
          }
        }
      );
}

static uint8_t CBOR_Spec_Raw_EverParse_get_header_major_type(CBOR_Spec_Raw_EverParse_header h)
{
  return h.fst.major_type;
}

static size_t Pulse_Lib_Slice_len__uint8_t(Pulse_Lib_Slice_slice__uint8_t s)
{
  return s.len;
}

static uint8_t
Pulse_Lib_Slice_op_Array_Access__uint8_t(Pulse_Lib_Slice_slice__uint8_t a, size_t i)
{
  return a.elt[i];
}

static bool CBOR_Pulse_Raw_EverParse_UTF8_impl_correct(Pulse_Lib_Slice_slice__uint8_t s)
{
  bool pres = true;
  size_t pi = (size_t)0U;
  size_t len = Pulse_Lib_Slice_len__uint8_t(s);
  bool cond;
  if (pres)
    cond = pi < len;
  else
    cond = false;
  while (cond)
  {
    size_t i = pi;
    uint8_t byte1 = Pulse_Lib_Slice_op_Array_Access__uint8_t(s, i);
    size_t i1 = i + (size_t)1U;
    if (byte1 <= 0x7FU)
      pi = i1;
    else if (i1 == len)
      pres = false;
    else
    {
      uint8_t byte2 = Pulse_Lib_Slice_op_Array_Access__uint8_t(s, i1);
      size_t i2 = i1 + (size_t)1U;
      if (0xC2U <= byte1 && byte1 <= 0xDFU && 0x80U <= byte2 && byte2 <= 0xBFU)
        pi = i2;
      else if (i2 == len)
        pres = false;
      else
      {
        uint8_t byte3 = Pulse_Lib_Slice_op_Array_Access__uint8_t(s, i2);
        size_t i3 = i2 + (size_t)1U;
        if (!(0x80U <= byte3 && byte3 <= 0xBFU))
          pres = false;
        else if (byte1 == 0xE0U)
          if (0xA0U <= byte2 && byte2 <= 0xBFU)
            pi = i3;
          else
            pres = false;
        else if (byte1 == 0xEDU)
          if (0x80U <= byte2 && byte2 <= 0x9FU)
            pi = i3;
          else
            pres = false;
        else if (0xE1U <= byte1 && byte1 <= 0xEFU && 0x80U <= byte2 && byte2 <= 0xBFU)
          pi = i3;
        else if (i3 == len)
          pres = false;
        else
        {
          uint8_t byte4 = Pulse_Lib_Slice_op_Array_Access__uint8_t(s, i3);
          size_t i4 = i3 + (size_t)1U;
          if (!(0x80U <= byte4 && byte4 <= 0xBFU))
            pres = false;
          else if (byte1 == 0xF0U && 0x90U <= byte2 && byte2 <= 0xBFU)
            pi = i4;
          else if (0xF1U <= byte1 && byte1 <= 0xF3U && 0x80U <= byte2 && byte2 <= 0xBFU)
            pi = i4;
          else if (byte1 == 0xF4U && 0x80U <= byte2 && byte2 <= 0x8FU)
            pi = i4;
          else
            pres = false;
        }
      }
    }
    bool ite;
    if (pres)
      ite = pi < len;
    else
      ite = false;
    cond = ite;
  }
  return pres;
}

static cbor_string CBOR_Pulse_Raw_Match_cbor_string_reset_perm(cbor_string c)
{
  return
    (
      (cbor_string){
        .cbor_string_type = c.cbor_string_type,
        .cbor_string_size = c.cbor_string_size,
        .cbor_string_ptr = c.cbor_string_ptr
      }
    );
}

static cbor_serialized CBOR_Pulse_Raw_Match_cbor_serialized_reset_perm(cbor_serialized c)
{
  return
    (
      (cbor_serialized){
        .cbor_serialized_header = c.cbor_serialized_header,
        .cbor_serialized_payload = c.cbor_serialized_payload
      }
    );
}

static cbor_tagged CBOR_Pulse_Raw_Match_cbor_tagged_reset_perm(cbor_tagged c)
{
  return
    ((cbor_tagged){ .cbor_tagged_tag = c.cbor_tagged_tag, .cbor_tagged_ptr = c.cbor_tagged_ptr });
}

static cbor_array CBOR_Pulse_Raw_Match_cbor_array_reset_perm(cbor_array c)
{
  return
    (
      (cbor_array){
        .cbor_array_length_size = c.cbor_array_length_size,
        .cbor_array_ptr = c.cbor_array_ptr
      }
    );
}

static cbor_map CBOR_Pulse_Raw_Match_cbor_map_reset_perm(cbor_map c)
{
  return
    ((cbor_map){ .cbor_map_length_size = c.cbor_map_length_size, .cbor_map_ptr = c.cbor_map_ptr });
}

static cbor_raw CBOR_Pulse_Raw_Match_cbor_raw_reset_perm_tot(cbor_raw c)
{
  if (c.tag == CBOR_Case_String)
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_String,
          {
            .case_CBOR_Case_String = CBOR_Pulse_Raw_Match_cbor_string_reset_perm(c.case_CBOR_Case_String)
          }
        }
      );
  else if (c.tag == CBOR_Case_Tagged)
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Tagged,
          {
            .case_CBOR_Case_Tagged = CBOR_Pulse_Raw_Match_cbor_tagged_reset_perm(c.case_CBOR_Case_Tagged)
          }
        }
      );
  else if (c.tag == CBOR_Case_Array)
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Array,
          {
            .case_CBOR_Case_Array = CBOR_Pulse_Raw_Match_cbor_array_reset_perm(c.case_CBOR_Case_Array)
          }
        }
      );
  else if (c.tag == CBOR_Case_Map)
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Map,
          { .case_CBOR_Case_Map = CBOR_Pulse_Raw_Match_cbor_map_reset_perm(c.case_CBOR_Case_Map) }
        }
      );
  else if (c.tag == CBOR_Case_Serialized_Tagged)
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Serialized_Tagged,
          {
            .case_CBOR_Case_Serialized_Tagged = CBOR_Pulse_Raw_Match_cbor_serialized_reset_perm(c.case_CBOR_Case_Serialized_Tagged)
          }
        }
      );
  else if (c.tag == CBOR_Case_Serialized_Array)
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Serialized_Array,
          {
            .case_CBOR_Case_Serialized_Array = CBOR_Pulse_Raw_Match_cbor_serialized_reset_perm(c.case_CBOR_Case_Serialized_Array)
          }
        }
      );
  else if (c.tag == CBOR_Case_Serialized_Map)
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Serialized_Map,
          {
            .case_CBOR_Case_Serialized_Map = CBOR_Pulse_Raw_Match_cbor_serialized_reset_perm(c.case_CBOR_Case_Serialized_Map)
          }
        }
      );
  else
    return c;
}

static CBOR_Spec_Raw_Base_raw_uint64 CBOR_Spec_Raw_Optimal_mk_raw_uint64(uint64_t x)
{
  uint8_t ite;
  if (x <= (uint64_t)MAX_SIMPLE_VALUE_ADDITIONAL_INFO)
    ite = 0U;
  else if (x < 256ULL)
    ite = 1U;
  else if (x < 65536ULL)
    ite = 2U;
  else if (x < 4294967296ULL)
    ite = 3U;
  else
    ite = 4U;
  return ((CBOR_Spec_Raw_Base_raw_uint64){ .size = ite, .value = x });
}

static int16_t CBOR_Pulse_Raw_Compare_Bytes_impl_uint8_compare(uint8_t x1, uint8_t x2)
{
  if (x1 < x2)
    return (int16_t)-1;
  else if (x1 > x2)
    return (int16_t)1;
  else
    return (int16_t)0;
}

static int16_t
CBOR_Pulse_Raw_Compare_Bytes_lex_compare_bytes(
  Pulse_Lib_Slice_slice__uint8_t s1,
  Pulse_Lib_Slice_slice__uint8_t s2
)
{
  Pulse_Lib_Slice_slice__uint8_t sp1 = s1;
  Pulse_Lib_Slice_slice__uint8_t sp2 = s2;
  size_t pi1 = (size_t)0U;
  size_t pi2 = (size_t)0U;
  size_t n1 = Pulse_Lib_Slice_len__uint8_t(sp1);
  size_t n2 = Pulse_Lib_Slice_len__uint8_t(sp2);
  int16_t ite;
  if ((size_t)0U < n1)
    if ((size_t)0U < n2)
      ite = (int16_t)0;
    else
      ite = (int16_t)1;
  else if ((size_t)0U < n2)
    ite = (int16_t)-1;
  else
    ite = (int16_t)0;
  int16_t pres = ite;
  while (pres == (int16_t)0 && pi1 < n1)
  {
    size_t i1 = pi1;
    uint8_t x1 = Pulse_Lib_Slice_op_Array_Access__uint8_t(sp1, i1);
    size_t i2 = pi2;
    int16_t
    c =
      CBOR_Pulse_Raw_Compare_Bytes_impl_uint8_compare(x1,
        Pulse_Lib_Slice_op_Array_Access__uint8_t(sp2, i2));
    if (c == (int16_t)0)
    {
      size_t i1_ = i1 + (size_t)1U;
      size_t i2_ = i2 + (size_t)1U;
      bool ci1_ = i1_ < n1;
      bool ci2_ = i2_ < n2;
      if (ci2_ && !ci1_)
        pres = (int16_t)-1;
      else if (ci1_ && !ci2_)
        pres = (int16_t)1;
      else
      {
        pi1 = i1_;
        pi2 = i2_;
      }
    }
    else
      pres = c;
  }
  return pres;
}

static CBOR_Spec_Raw_EverParse_initial_byte_t
CBOR_Pulse_Raw_EverParse_Format_read_initial_byte_t(Pulse_Lib_Slice_slice__uint8_t input)
{
  uint8_t x = Pulse_Lib_Slice_op_Array_Access__uint8_t(input, (size_t)0U);
  return
    (
      (CBOR_Spec_Raw_EverParse_initial_byte_t){
        .major_type = LowParse_BitFields_get_bitfield_gen8(x, 5U, 8U),
        .additional_info = LowParse_BitFields_get_bitfield_gen8(x, 0U, 5U)
      }
    );
}

typedef struct K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t_s
{
  Pulse_Lib_Slice_slice__uint8_t fst;
  Pulse_Lib_Slice_slice__uint8_t snd;
}
K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t;

static K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
Pulse_Lib_Slice_split__uint8_t(Pulse_Lib_Slice_slice__uint8_t s, size_t i)
{
  return
    (
      (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
        .fst = { .elt = s.elt, .len = i },
        .snd = { .elt = s.elt + i, .len = s.len - i }
      }
    );
}

static CBOR_Spec_Raw_EverParse_header
CBOR_Pulse_Raw_EverParse_Format_read_header(Pulse_Lib_Slice_slice__uint8_t input)
{
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut = Pulse_Lib_Slice_split__uint8_t(input, (size_t)1U);
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
  Pulse_Lib_Slice_slice__uint8_t input2 = scrut1.snd;
  CBOR_Spec_Raw_EverParse_initial_byte_t
  x1 = CBOR_Pulse_Raw_EverParse_Format_read_initial_byte_t(scrut1.fst);
  CBOR_Spec_Raw_EverParse_long_argument ite;
  if (x1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS)
    if (x1.major_type == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
      ite =
        (
          (CBOR_Spec_Raw_EverParse_long_argument){
            .tag = CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue,
            {
              .case_LongArgumentSimpleValue = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2,
                (size_t)0U)
            }
          }
        );
    else
      ite =
        (
          (CBOR_Spec_Raw_EverParse_long_argument){
            .tag = CBOR_Spec_Raw_EverParse_LongArgumentU8,
            { .case_LongArgumentU8 = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)0U) }
          }
        );
  else if (x1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_16_BITS)
  {
    uint8_t last = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)1U);
    ite =
      (
        (CBOR_Spec_Raw_EverParse_long_argument){
          .tag = CBOR_Spec_Raw_EverParse_LongArgumentU16,
          {
            .case_LongArgumentU16 = (uint32_t)(uint16_t)last +
              (uint32_t)(uint16_t)Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)0U) *
                256U
          }
        }
      );
  }
  else if (x1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_32_BITS)
  {
    uint8_t last = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)3U);
    uint8_t last1 = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)3U - (size_t)1U);
    uint8_t
    last2 = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)3U - (size_t)1U - (size_t)1U);
    ite =
      (
        (CBOR_Spec_Raw_EverParse_long_argument){
          .tag = CBOR_Spec_Raw_EverParse_LongArgumentU32,
          {
            .case_LongArgumentU32 = (uint32_t)last +
              ((uint32_t)last1 +
                ((uint32_t)last2 +
                  (uint32_t)Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)0U) * 256U)
                * 256U)
              * 256U
          }
        }
      );
  }
  else if (x1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_64_BITS)
  {
    uint8_t last = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)7U);
    uint8_t last1 = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)7U - (size_t)1U);
    uint8_t
    last2 = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)7U - (size_t)1U - (size_t)1U);
    uint8_t
    last3 =
      Pulse_Lib_Slice_op_Array_Access__uint8_t(input2,
        (size_t)7U - (size_t)1U - (size_t)1U - (size_t)1U);
    size_t pos_4 = (size_t)7U - (size_t)1U - (size_t)1U - (size_t)1U - (size_t)1U;
    uint8_t last4 = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, pos_4);
    size_t pos_5 = pos_4 - (size_t)1U;
    uint8_t last5 = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, pos_5);
    uint8_t last6 = Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, pos_5 - (size_t)1U);
    ite =
      (
        (CBOR_Spec_Raw_EverParse_long_argument){
          .tag = CBOR_Spec_Raw_EverParse_LongArgumentU64,
          {
            .case_LongArgumentU64 = (uint64_t)last +
              ((uint64_t)last1 +
                ((uint64_t)last2 +
                  ((uint64_t)last3 +
                    ((uint64_t)last4 +
                      ((uint64_t)last5 +
                        ((uint64_t)last6 +
                          (uint64_t)Pulse_Lib_Slice_op_Array_Access__uint8_t(input2, (size_t)0U) *
                            256ULL)
                        * 256ULL)
                      * 256ULL)
                    * 256ULL)
                  * 256ULL)
                * 256ULL)
              * 256ULL
          }
        }
      );
  }
  else
    ite =
      ((CBOR_Spec_Raw_EverParse_long_argument){ .tag = CBOR_Spec_Raw_EverParse_LongArgumentOther });
  return ((CBOR_Spec_Raw_EverParse_header){ .fst = x1, .snd = ite });
}

static bool
CBOR_Pulse_Raw_EverParse_Format_validate_header(
  Pulse_Lib_Slice_slice__uint8_t input,
  size_t *poffset
)
{
  size_t offset1 = *poffset;
  size_t offset2 = *poffset;
  size_t offset30 = *poffset;
  bool ite0;
  if (Pulse_Lib_Slice_len__uint8_t(input) - offset30 < (size_t)1U)
    ite0 = false;
  else
  {
    *poffset = offset30 + (size_t)1U;
    ite0 = true;
  }
  bool ite1;
  if (ite0)
  {
    size_t off = *poffset;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut = Pulse_Lib_Slice_split__uint8_t(input, offset2);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 =
      Pulse_Lib_Slice_split__uint8_t((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut.fst,
            .snd = scrut.snd
          }
        ).snd,
        off - offset2);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
    CBOR_Spec_Raw_EverParse_initial_byte_t
    x =
      CBOR_Pulse_Raw_EverParse_Format_read_initial_byte_t((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut1.fst,
            .snd = scrut1.snd
          }
        ).fst);
    bool ite;
    if (x.major_type == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
      ite = x.additional_info <= CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS;
    else
      ite = true;
    ite1 = ite && x.additional_info < CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_UNASSIGNED_MIN;
  }
  else
    ite1 = false;
  if (ite1)
  {
    size_t off = *poffset;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 = Pulse_Lib_Slice_split__uint8_t(input, offset1);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 =
      Pulse_Lib_Slice_split__uint8_t((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut0.fst,
            .snd = scrut0.snd
          }
        ).snd,
        off - offset1);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
    CBOR_Spec_Raw_EverParse_initial_byte_t
    x =
      CBOR_Pulse_Raw_EverParse_Format_read_initial_byte_t((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut2.fst,
            .snd = scrut2.snd
          }
        ).fst);
    if (x.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS)
      if (x.major_type == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
      {
        size_t offset2 = *poffset;
        size_t offset3 = *poffset;
        bool ite;
        if (Pulse_Lib_Slice_len__uint8_t(input) - offset3 < (size_t)1U)
          ite = false;
        else
        {
          *poffset = offset3 + (size_t)1U;
          ite = true;
        }
        if (ite)
        {
          size_t off1 = *poffset;
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut = Pulse_Lib_Slice_split__uint8_t(input, offset2);
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut0 =
            Pulse_Lib_Slice_split__uint8_t((
                (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                  .fst = scrut.fst,
                  .snd = scrut.snd
                }
              ).snd,
              off1 - offset2);
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
          return
            MIN_SIMPLE_VALUE_LONG_ARGUMENT <=
              Pulse_Lib_Slice_op_Array_Access__uint8_t((
                  (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                    .fst = scrut1.fst,
                    .snd = scrut1.snd
                  }
                ).fst,
                (size_t)0U);
        }
        else
          return false;
      }
      else
      {
        size_t offset2 = *poffset;
        if (Pulse_Lib_Slice_len__uint8_t(input) - offset2 < (size_t)1U)
          return false;
        else
        {
          *poffset = offset2 + (size_t)1U;
          return true;
        }
      }
    else if (x.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_16_BITS)
    {
      size_t offset2 = *poffset;
      if (Pulse_Lib_Slice_len__uint8_t(input) - offset2 < (size_t)2U)
        return false;
      else
      {
        *poffset = offset2 + (size_t)2U;
        return true;
      }
    }
    else if (x.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_32_BITS)
    {
      size_t offset2 = *poffset;
      if (Pulse_Lib_Slice_len__uint8_t(input) - offset2 < (size_t)4U)
        return false;
      else
      {
        *poffset = offset2 + (size_t)4U;
        return true;
      }
    }
    else if (x.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_64_BITS)
    {
      size_t offset2 = *poffset;
      if (Pulse_Lib_Slice_len__uint8_t(input) - offset2 < (size_t)8U)
        return false;
      else
      {
        *poffset = offset2 + (size_t)8U;
        return true;
      }
    }
    else
      return true;
  }
  else
    return false;
}

static size_t
CBOR_Pulse_Raw_EverParse_Format_jump_header(
  Pulse_Lib_Slice_slice__uint8_t input,
  size_t offset
)
{
  size_t off1 = offset + (size_t)1U;
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut = Pulse_Lib_Slice_split__uint8_t(input, offset);
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 =
    Pulse_Lib_Slice_split__uint8_t((
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut.fst,
          .snd = scrut.snd
        }
      ).snd,
      off1 - offset);
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
  CBOR_Spec_Raw_EverParse_initial_byte_t
  x =
    CBOR_Pulse_Raw_EverParse_Format_read_initial_byte_t((
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut1.fst,
          .snd = scrut1.snd
        }
      ).fst);
  if (x.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS)
    return off1 + (size_t)1U;
  else if (x.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_16_BITS)
    return off1 + (size_t)2U;
  else if (x.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_32_BITS)
    return off1 + (size_t)4U;
  else if (x.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_64_BITS)
    return off1 + (size_t)8U;
  else
    return off1 + (size_t)0U;
}

static bool
CBOR_Pulse_Raw_EverParse_Format_validate_recursive_step_count_leaf(
  Pulse_Lib_Slice_slice__uint8_t a,
  size_t bound,
  size_t *prem
)
{
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut =
    Pulse_Lib_Slice_split__uint8_t(a,
      CBOR_Pulse_Raw_EverParse_Format_jump_header(a, (size_t)0U));
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
  CBOR_Spec_Raw_EverParse_header
  h =
    CBOR_Pulse_Raw_EverParse_Format_read_header((
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut0.fst,
          .snd = scrut0.snd
        }
      ).fst);
  uint8_t typ = CBOR_Spec_Raw_EverParse_get_header_major_type(h);
  if (typ == CBOR_MAJOR_TYPE_ARRAY)
  {
    *prem = (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h.fst, h.snd);
    return false;
  }
  else if (typ == CBOR_MAJOR_TYPE_MAP)
  {
    size_t arg = (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h.fst, h.snd);
    if (arg > bound)
      return true;
    else if (bound - arg < arg)
      return true;
    else
    {
      *prem = arg + arg;
      return false;
    }
  }
  else if (typ == CBOR_MAJOR_TYPE_TAGGED)
  {
    *prem = (size_t)1U;
    return false;
  }
  else
  {
    *prem = (size_t)0U;
    return false;
  }
}

static size_t
CBOR_Pulse_Raw_EverParse_Format_impl_remaining_data_items_header(
  CBOR_Spec_Raw_EverParse_header h
)
{
  uint8_t typ = CBOR_Spec_Raw_EverParse_get_header_major_type(h);
  if (typ == CBOR_MAJOR_TYPE_ARRAY)
    return (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h.fst, h.snd);
  else if (typ == CBOR_MAJOR_TYPE_MAP)
  {
    size_t arg = (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h.fst, h.snd);
    return arg + arg;
  }
  else if (typ == CBOR_MAJOR_TYPE_TAGGED)
    return (size_t)1U;
  else
    return (size_t)0U;
}

static size_t
CBOR_Pulse_Raw_EverParse_Format_jump_recursive_step_count_leaf(
  Pulse_Lib_Slice_slice__uint8_t a
)
{
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut =
    Pulse_Lib_Slice_split__uint8_t(a,
      CBOR_Pulse_Raw_EverParse_Format_jump_header(a, (size_t)0U));
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
  return
    CBOR_Pulse_Raw_EverParse_Format_impl_remaining_data_items_header(CBOR_Pulse_Raw_EverParse_Format_read_header((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut0.fst,
            .snd = scrut0.snd
          }
        ).fst));
}

static bool
CBOR_Pulse_Raw_EverParse_Format_validate_raw_data_item(
  Pulse_Lib_Slice_slice__uint8_t input,
  size_t *poffset
)
{
  size_t pn = (size_t)1U;
  bool pres = true;
  while (pres && pn > (size_t)0U)
  {
    size_t off = *poffset;
    size_t n = pn;
    if (n > Pulse_Lib_Slice_len__uint8_t(input) - off)
      pres = false;
    else
    {
      size_t offset1 = *poffset;
      bool ite0;
      if (CBOR_Pulse_Raw_EverParse_Format_validate_header(input, poffset))
      {
        size_t off1 = *poffset;
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut0 = Pulse_Lib_Slice_split__uint8_t(input, offset1);
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut1 =
          Pulse_Lib_Slice_split__uint8_t((
              (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                .fst = scrut0.fst,
                .snd = scrut0.snd
              }
            ).snd,
            off1 - offset1);
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
        CBOR_Spec_Raw_EverParse_header
        x =
          CBOR_Pulse_Raw_EverParse_Format_read_header((
              (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                .fst = scrut2.fst,
                .snd = scrut2.snd
              }
            ).fst);
        CBOR_Spec_Raw_EverParse_initial_byte_t b = x.fst;
        if
        (b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING || b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING)
        {
          size_t n1 = (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(x.fst, x.snd);
          size_t offset2 = *poffset;
          size_t offset3 = *poffset;
          bool ite;
          if (Pulse_Lib_Slice_len__uint8_t(input) - offset3 < n1)
            ite = false;
          else
          {
            *poffset = offset3 + n1;
            ite = true;
          }
          if (ite)
          {
            size_t off2 = *poffset;
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut = Pulse_Lib_Slice_split__uint8_t(input, offset2);
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut0 =
              Pulse_Lib_Slice_split__uint8_t((
                  (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                    .fst = scrut.fst,
                    .snd = scrut.snd
                  }
                ).snd,
                off2 - offset2);
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
            Pulse_Lib_Slice_slice__uint8_t
            x1 =
              (
                (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                  .fst = scrut1.fst,
                  .snd = scrut1.snd
                }
              ).fst;
            if (CBOR_Spec_Raw_EverParse_get_header_major_type(x) == CBOR_MAJOR_TYPE_BYTE_STRING)
              ite0 = true;
            else
              ite0 = CBOR_Pulse_Raw_EverParse_UTF8_impl_correct(x1);
          }
          else
            ite0 = false;
        }
        else
          ite0 = true;
      }
      else
        ite0 = false;
      if (!ite0)
        pres = false;
      else
      {
        size_t offset1 = *poffset;
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut = Pulse_Lib_Slice_split__uint8_t(input, off);
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut0 =
          Pulse_Lib_Slice_split__uint8_t((
              (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                .fst = scrut.fst,
                .snd = scrut.snd
              }
            ).snd,
            offset1 - off);
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
        Pulse_Lib_Slice_slice__uint8_t
        input1 =
          (
            (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
              .fst = scrut1.fst,
              .snd = scrut1.snd
            }
          ).fst;
        size_t bound = Pulse_Lib_Slice_len__uint8_t(input) - off - n;
        bool
        res2 =
          CBOR_Pulse_Raw_EverParse_Format_validate_recursive_step_count_leaf(input1,
            bound,
            &pn);
        size_t count = pn;
        if (res2 || count > bound)
          pres = false;
        else
          pn = n - (size_t)1U + count;
      }
    }
  }
  return pres;
}

static size_t
CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(
  Pulse_Lib_Slice_slice__uint8_t input,
  size_t offset
)
{
  size_t poffset = offset;
  size_t pn = (size_t)1U;
  while (pn > (size_t)0U)
  {
    size_t off = poffset;
    size_t off10 = CBOR_Pulse_Raw_EverParse_Format_jump_header(input, off);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 = Pulse_Lib_Slice_split__uint8_t(input, off);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 =
      Pulse_Lib_Slice_split__uint8_t((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut0.fst,
            .snd = scrut0.snd
          }
        ).snd,
        off10 - off);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
    CBOR_Spec_Raw_EverParse_header
    x =
      CBOR_Pulse_Raw_EverParse_Format_read_header((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut2.fst,
            .snd = scrut2.snd
          }
        ).fst);
    CBOR_Spec_Raw_EverParse_initial_byte_t b = x.fst;
    size_t off1;
    if (b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING || b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING)
      off1 = off10 + (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(x.fst, x.snd);
    else
      off1 = off10 + (size_t)0U;
    poffset = off1;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut = Pulse_Lib_Slice_split__uint8_t(input, off);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut3 =
      Pulse_Lib_Slice_split__uint8_t((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut.fst,
            .snd = scrut.snd
          }
        ).snd,
        off1 - off);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
    Pulse_Lib_Slice_slice__uint8_t
    input1 =
      (
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut4.fst,
          .snd = scrut4.snd
        }
      ).fst;
    size_t n = pn;
    size_t unused = Pulse_Lib_Slice_len__uint8_t(input) - off1;
    KRML_MAYBE_UNUSED_VAR(unused);
    pn = n - (size_t)1U + CBOR_Pulse_Raw_EverParse_Format_jump_recursive_step_count_leaf(input1);
  }
  return poffset;
}

static cbor_raw
CBOR_Pulse_Raw_EverParse_Serialized_Base_cbor_read(Pulse_Lib_Slice_slice__uint8_t input)
{
  CBOR_Spec_Raw_EverParse_header
  ph =
    {
      .fst = { .major_type = CBOR_MAJOR_TYPE_SIMPLE_VALUE, .additional_info = 0U },
      .snd = { .tag = CBOR_Spec_Raw_EverParse_LongArgumentOther }
    };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut =
    Pulse_Lib_Slice_split__uint8_t(input,
      CBOR_Pulse_Raw_EverParse_Format_jump_header(input, (size_t)0U));
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
  Pulse_Lib_Slice_slice__uint8_t outc = scrut1.snd;
  ph = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut1.fst);
  Pulse_Lib_Slice_slice__uint8_t pc = outc;
  CBOR_Spec_Raw_EverParse_header h = ph;
  uint8_t typ = h.fst.major_type;
  if (typ == CBOR_MAJOR_TYPE_UINT64 || typ == CBOR_MAJOR_TYPE_NEG_INT64)
  {
    CBOR_Spec_Raw_EverParse_initial_byte_t b = h.fst;
    CBOR_Spec_Raw_EverParse_long_argument l = h.snd;
    CBOR_Spec_Raw_Base_raw_uint64 i;
    if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU8)
      i = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 1U, .value = (uint64_t)l.case_LongArgumentU8 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU16)
      i = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 2U, .value = (uint64_t)l.case_LongArgumentU16 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU32)
      i = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 3U, .value = (uint64_t)l.case_LongArgumentU32 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU64)
      i = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 4U, .value = l.case_LongArgumentU64 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
      i = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 0U, .value = (uint64_t)b.additional_info });
    else
      i =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Int,
          {
            .case_CBOR_Case_Int = {
              .cbor_int_type = typ,
              .cbor_int_size = i.size,
              .cbor_int_value = i.value
            }
          }
        }
      );
  }
  else if (typ == CBOR_MAJOR_TYPE_TEXT_STRING || typ == CBOR_MAJOR_TYPE_BYTE_STRING)
  {
    CBOR_Spec_Raw_EverParse_initial_byte_t b = h.fst;
    CBOR_Spec_Raw_EverParse_long_argument l = h.snd;
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU8)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 1U, .value = (uint64_t)l.case_LongArgumentU8 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU16)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 2U, .value = (uint64_t)l.case_LongArgumentU16 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU32)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 3U, .value = (uint64_t)l.case_LongArgumentU32 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU64)
      ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 4U, .value = l.case_LongArgumentU64 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
      ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 0U, .value = (uint64_t)b.additional_info });
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_String,
          {
            .case_CBOR_Case_String = {
              .cbor_string_type = typ,
              .cbor_string_size = ite.size,
              .cbor_string_ptr = pc
            }
          }
        }
      );
  }
  else if (typ == CBOR_MAJOR_TYPE_TAGGED)
  {
    CBOR_Spec_Raw_EverParse_initial_byte_t b = h.fst;
    CBOR_Spec_Raw_EverParse_long_argument l = h.snd;
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU8)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 1U, .value = (uint64_t)l.case_LongArgumentU8 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU16)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 2U, .value = (uint64_t)l.case_LongArgumentU16 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU32)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 3U, .value = (uint64_t)l.case_LongArgumentU32 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU64)
      ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 4U, .value = l.case_LongArgumentU64 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
      ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 0U, .value = (uint64_t)b.additional_info });
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Serialized_Tagged,
          {
            .case_CBOR_Case_Serialized_Tagged = {
              .cbor_serialized_header = ite,
              .cbor_serialized_payload = pc
            }
          }
        }
      );
  }
  else if (typ == CBOR_MAJOR_TYPE_ARRAY)
  {
    CBOR_Spec_Raw_EverParse_initial_byte_t b = h.fst;
    CBOR_Spec_Raw_EverParse_long_argument l = h.snd;
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU8)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 1U, .value = (uint64_t)l.case_LongArgumentU8 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU16)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 2U, .value = (uint64_t)l.case_LongArgumentU16 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU32)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 3U, .value = (uint64_t)l.case_LongArgumentU32 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU64)
      ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 4U, .value = l.case_LongArgumentU64 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
      ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 0U, .value = (uint64_t)b.additional_info });
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Serialized_Array,
          {
            .case_CBOR_Case_Serialized_Array = {
              .cbor_serialized_header = ite,
              .cbor_serialized_payload = pc
            }
          }
        }
      );
  }
  else if (typ == CBOR_MAJOR_TYPE_MAP)
  {
    CBOR_Spec_Raw_EverParse_initial_byte_t b = h.fst;
    CBOR_Spec_Raw_EverParse_long_argument l = h.snd;
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU8)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 1U, .value = (uint64_t)l.case_LongArgumentU8 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU16)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 2U, .value = (uint64_t)l.case_LongArgumentU16 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU32)
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 3U, .value = (uint64_t)l.case_LongArgumentU32 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentU64)
      ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 4U, .value = l.case_LongArgumentU64 });
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
      ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = 0U, .value = (uint64_t)b.additional_info });
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return
      (
        (cbor_raw){
          .tag = CBOR_Case_Serialized_Map,
          {
            .case_CBOR_Case_Serialized_Map = {
              .cbor_serialized_header = ite,
              .cbor_serialized_payload = pc
            }
          }
        }
      );
  }
  else
  {
    CBOR_Spec_Raw_EverParse_initial_byte_t b = h.fst;
    CBOR_Spec_Raw_EverParse_long_argument l = h.snd;
    uint8_t ite;
    if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
      ite = b.additional_info;
    else if (l.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
      ite = l.case_LongArgumentSimpleValue;
    else
      ite = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
    return ((cbor_raw){ .tag = CBOR_Case_Simple, { .case_CBOR_Case_Simple = ite } });
  }
}

static cbor_raw
CBOR_Pulse_Raw_Format_Parse_cbor_parse(Pulse_Lib_Slice_slice__uint8_t input, size_t len)
{
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut = Pulse_Lib_Slice_split__uint8_t(input, (size_t)0U);
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 =
    Pulse_Lib_Slice_split__uint8_t((
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut.fst,
          .snd = scrut.snd
        }
      ).snd,
      len - (size_t)0U);
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
  return
    CBOR_Pulse_Raw_EverParse_Serialized_Base_cbor_read((
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut1.fst,
          .snd = scrut1.snd
        }
      ).fst);
}

static cbor_raw
CBOR_Pulse_Raw_Format_Serialized_cbor_match_serialized_tagged_get_payload(cbor_serialized c)
{
  return CBOR_Pulse_Raw_EverParse_Serialized_Base_cbor_read(c.cbor_serialized_payload);
}

static cbor_raw
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_item(cbor_serialized c, uint64_t i)
{
  size_t pi = (size_t)0U;
  Pulse_Lib_Slice_slice__uint8_t pres = c.cbor_serialized_payload;
  while (pi < (size_t)i)
  {
    Pulse_Lib_Slice_slice__uint8_t res = pres;
    size_t i1 = pi;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut =
      Pulse_Lib_Slice_split__uint8_t(res,
        CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(res, (size_t)0U));
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
    Pulse_Lib_Slice_slice__uint8_t
    res2 =
      (
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut1.fst,
          .snd = scrut1.snd
        }
      ).snd;
    pi = i1 + (size_t)1U;
    pres = res2;
  }
  Pulse_Lib_Slice_slice__uint8_t res = pres;
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut =
    Pulse_Lib_Slice_split__uint8_t(res,
      CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(res, (size_t)0U));
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
  return
    CBOR_Pulse_Raw_EverParse_Serialized_Base_cbor_read((
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut1.fst,
          .snd = scrut1.snd
        }
      ).fst);
}

static CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_init(cbor_serialized c)
{
  return
    (
      (CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator){
        .s = c.cbor_serialized_payload,
        .len = c.cbor_serialized_header.value
      }
    );
}

static bool
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator c
)
{
  return c.len == 0ULL;
}

static uint64_t
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_length(
  CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator c
)
{
  return c.len;
}

static cbor_raw
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw *pi,
  CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator i
)
{
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut =
    Pulse_Lib_Slice_split__uint8_t(i.s,
      CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(i.s, (size_t)0U));
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
  Pulse_Lib_Slice_slice__uint8_t s2 = scrut2.snd;
  cbor_raw res = CBOR_Pulse_Raw_EverParse_Serialized_Base_cbor_read(scrut2.fst);
  *pi =
    (
      (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw){
        .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized,
        { .case_CBOR_Raw_Iterator_Serialized = { .s = s2, .len = i.len - 1ULL } }
      }
    );
  return res;
}

static CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_truncate(
  CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator c,
  uint64_t len
)
{
  return ((CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator){ .s = c.s, .len = len });
}

static CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_map_iterator_init(cbor_serialized c)
{
  return
    (
      (CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator){
        .s = c.cbor_serialized_payload,
        .len = c.cbor_serialized_header.value
      }
    );
}

static bool
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_map_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator c
)
{
  return c.len == 0ULL;
}

static cbor_map_entry
CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_map_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry *pi,
  CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator i
)
{
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut0 =
    Pulse_Lib_Slice_split__uint8_t(i.s,
      CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(i.s,
        CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(i.s, (size_t)0U)));
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
  Pulse_Lib_Slice_slice__uint8_t s1 = scrut3.fst;
  Pulse_Lib_Slice_slice__uint8_t s2 = scrut3.snd;
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut =
    Pulse_Lib_Slice_split__uint8_t(s1,
      CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(s1, (size_t)0U));
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut4 = { .fst = scrut.fst, .snd = scrut.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut5 = { .fst = scrut4.fst, .snd = scrut4.snd };
  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
  scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
  Pulse_Lib_Slice_slice__uint8_t s21 = scrut6.snd;
  cbor_raw res1 = CBOR_Pulse_Raw_EverParse_Serialized_Base_cbor_read(scrut6.fst);
  cbor_map_entry
  res =
    {
      .cbor_map_entry_key = res1,
      .cbor_map_entry_value = CBOR_Pulse_Raw_EverParse_Serialized_Base_cbor_read(s21)
    };
  *pi =
    (
      (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry){
        .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized,
        { .case_CBOR_Raw_Iterator_Serialized = { .s = s2, .len = i.len - 1ULL } }
      }
    );
  return res;
}

static cbor_raw CBOR_Pulse_Raw_Read_cbor_match_tagged_get_payload(cbor_raw c)
{
  if (c.tag == CBOR_Case_Serialized_Tagged)
    return
      CBOR_Pulse_Raw_Format_Serialized_cbor_match_serialized_tagged_get_payload(c.case_CBOR_Case_Serialized_Tagged);
  else if (c.tag == CBOR_Case_Tagged)
    return *c.case_CBOR_Case_Tagged.cbor_tagged_ptr;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static cbor_raw
Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_raw(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw a,
  size_t i
)
{
  return a.elt[i];
}

static cbor_raw CBOR_Pulse_Raw_Read_cbor_array_item(cbor_raw c, uint64_t i)
{
  if (c.tag == CBOR_Case_Serialized_Array)
    return
      CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_item(c.case_CBOR_Case_Serialized_Array,
        i);
  else if (c.tag == CBOR_Case_Array)
    return
      Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_raw(c.case_CBOR_Case_Array.cbor_array_ptr,
        (size_t)i);
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
CBOR_Pulse_Raw_Read_cbor_array_iterator_init(cbor_raw c)
{
  if (c.tag == CBOR_Case_Serialized_Array)
    return
      (
        (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw){
          .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized,
          {
            .case_CBOR_Raw_Iterator_Serialized = CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_init(c.case_CBOR_Case_Serialized_Array)
          }
        }
      );
  else if (c.tag == CBOR_Case_Array)
    return
      (
        (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw){
          .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice,
          { .case_CBOR_Raw_Iterator_Slice = c.case_CBOR_Case_Array.cbor_array_ptr }
        }
      );
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static size_t
Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw s
)
{
  return s.len;
}

static bool
CBOR_Pulse_Raw_Read_cbor_array_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw c
)
{
  if (c.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice)
    return
      Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(c.case_CBOR_Raw_Iterator_Slice) ==
        (size_t)0U;
  else if (c.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized)
    return
      CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_is_empty(c.case_CBOR_Raw_Iterator_Serialized);
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static uint64_t
CBOR_Pulse_Raw_Read_cbor_array_iterator_length(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw c
)
{
  if (c.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice)
    return
      (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(c.case_CBOR_Raw_Iterator_Slice);
  else if (c.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized)
    return
      CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_length(c.case_CBOR_Raw_Iterator_Serialized);
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

typedef struct
K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_s
{
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw fst;
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw snd;
}
K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw;

static K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw
Pulse_Lib_Slice_split__CBOR_Pulse_Raw_Type_cbor_raw(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw s,
  size_t i
)
{
  return
    (
      (K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw){
        .fst = { .elt = s.elt, .len = i },
        .snd = { .elt = s.elt + i, .len = s.len - i }
      }
    );
}

static cbor_raw
CBOR_Pulse_Raw_Read_cbor_array_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw *pi
)
{
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw scrut = *pi;
  if (scrut.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice)
  {
    Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw i1 = scrut.case_CBOR_Raw_Iterator_Slice;
    cbor_raw res = Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_raw(i1, (size_t)0U);
    *pi =
      (
        (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw){
          .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice,
          {
            .case_CBOR_Raw_Iterator_Slice = Pulse_Lib_Slice_split__CBOR_Pulse_Raw_Type_cbor_raw(i1,
              (size_t)1U).snd
          }
        }
      );
    return res;
  }
  else if (scrut.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized)
    return
      CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_next(pi,
        scrut.case_CBOR_Raw_Iterator_Serialized);
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
CBOR_Pulse_Raw_Read_cbor_array_iterator_truncate(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw c,
  uint64_t len
)
{
  if (c.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice)
  {
    K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw
    scrut =
      Pulse_Lib_Slice_split__CBOR_Pulse_Raw_Type_cbor_raw(c.case_CBOR_Raw_Iterator_Slice,
        (size_t)len);
    return
      (
        (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw){
          .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice,
          {
            .case_CBOR_Raw_Iterator_Slice = (
              (K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw){
                .fst = scrut.fst,
                .snd = scrut.snd
              }
            ).fst
          }
        }
      );
  }
  else if (c.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized)
    return
      (
        (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw){
          .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized,
          {
            .case_CBOR_Raw_Iterator_Serialized = CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_array_iterator_truncate(c.case_CBOR_Raw_Iterator_Serialized,
              len)
          }
        }
      );
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
CBOR_Pulse_Raw_Read_cbor_map_iterator_init(cbor_raw c)
{
  if (c.tag == CBOR_Case_Serialized_Map)
    return
      (
        (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry){
          .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized,
          {
            .case_CBOR_Raw_Iterator_Serialized = CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_map_iterator_init(c.case_CBOR_Case_Serialized_Map)
          }
        }
      );
  else if (c.tag == CBOR_Case_Map)
    return
      (
        (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry){
          .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice,
          { .case_CBOR_Raw_Iterator_Slice = c.case_CBOR_Case_Map.cbor_map_ptr }
        }
      );
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static size_t
Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry s
)
{
  return s.len;
}

static bool
CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry c
)
{
  if (c.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice)
    return
      Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(c.case_CBOR_Raw_Iterator_Slice) ==
        (size_t)0U;
  else if (c.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized)
    return
      CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_map_iterator_is_empty(c.case_CBOR_Raw_Iterator_Serialized);
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static cbor_map_entry
Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_map_entry(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry a,
  size_t i
)
{
  return a.elt[i];
}

typedef struct
K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry_s
{
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry fst;
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry snd;
}
K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry;

static K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry
Pulse_Lib_Slice_split__CBOR_Pulse_Raw_Type_cbor_map_entry(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry s,
  size_t i
)
{
  return
    (
      (K___Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry){
        .fst = { .elt = s.elt, .len = i },
        .snd = { .elt = s.elt + i, .len = s.len - i }
      }
    );
}

static cbor_map_entry
CBOR_Pulse_Raw_Read_cbor_map_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry *pi
)
{
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry scrut = *pi;
  if (scrut.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice)
  {
    Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry
    i1 = scrut.case_CBOR_Raw_Iterator_Slice;
    cbor_map_entry
    res = Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_map_entry(i1, (size_t)0U);
    *pi =
      (
        (CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry){
          .tag = CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice,
          {
            .case_CBOR_Raw_Iterator_Slice = Pulse_Lib_Slice_split__CBOR_Pulse_Raw_Type_cbor_map_entry(i1,
              (size_t)1U).snd
          }
        }
      );
    return res;
  }
  else if (scrut.tag == CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized)
    return
      CBOR_Pulse_Raw_Format_Serialized_cbor_serialized_map_iterator_next(pi,
        scrut.case_CBOR_Raw_Iterator_Serialized);
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static CBOR_Spec_Raw_EverParse_initial_byte_t
Prims___proj__Mkdtuple2__item___1__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
  CBOR_Spec_Raw_EverParse_header pair
)
{
  return pair.fst;
}

static CBOR_Spec_Raw_EverParse_initial_byte_t
FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
  CBOR_Spec_Raw_EverParse_header t
)
{
  return
    Prims___proj__Mkdtuple2__item___1__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(t);
}

static void
Pulse_Lib_Slice_op_Array_Assignment__uint8_t(
  Pulse_Lib_Slice_slice__uint8_t a,
  size_t i,
  uint8_t v
)
{
  a.elt[i] = v;
}

static CBOR_Spec_Raw_EverParse_long_argument
Prims___proj__Mkdtuple2__item___2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
  CBOR_Spec_Raw_EverParse_header pair
)
{
  return pair.snd;
}

static CBOR_Spec_Raw_EverParse_long_argument
FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(
  CBOR_Spec_Raw_EverParse_header t
)
{
  return
    Prims___proj__Mkdtuple2__item___2__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(t);
}

static size_t
CBOR_Pulse_Raw_Format_Serialize_write_header(
  CBOR_Spec_Raw_EverParse_header x,
  Pulse_Lib_Slice_slice__uint8_t out,
  size_t offset
)
{
  CBOR_Spec_Raw_EverParse_initial_byte_t
  xh1 =
    FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(x);
  size_t pos_ = offset + (size_t)1U;
  Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out,
    pos_ - (size_t)1U,
    LowParse_BitFields_set_bitfield_gen8(LowParse_BitFields_set_bitfield_gen8(0U,
        0U,
        5U,
        xh1.additional_info),
      5U,
      8U,
      xh1.major_type));
  size_t res1 = pos_;
  CBOR_Spec_Raw_EverParse_long_argument
  x2_ =
    FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(x);
  if (xh1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS)
    if (xh1.major_type == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
    {
      size_t pos_ = res1 + (size_t)1U;
      uint8_t ite;
      if (x2_.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
        ite = x2_.case_LongArgumentSimpleValue;
      else
        ite = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
      Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_ - (size_t)1U, ite);
      return pos_;
    }
    else
    {
      size_t pos_ = res1 + (size_t)1U;
      uint8_t ite;
      if (x2_.tag == CBOR_Spec_Raw_EverParse_LongArgumentU8)
        ite = x2_.case_LongArgumentU8;
      else
        ite = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
      Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_ - (size_t)1U, ite);
      return pos_;
    }
  else if (xh1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_16_BITS)
  {
    size_t pos_ = res1 + (size_t)2U;
    uint16_t ite0;
    if (x2_.tag == CBOR_Spec_Raw_EverParse_LongArgumentU16)
      ite0 = x2_.case_LongArgumentU16;
    else
      ite0 = KRML_EABORT(uint16_t, "unreachable (pattern matches are exhaustive in F*)");
    uint8_t lo = (uint8_t)ite0;
    size_t pos_1 = pos_ - (size_t)1U;
    uint16_t ite;
    if (x2_.tag == CBOR_Spec_Raw_EverParse_LongArgumentU16)
      ite = x2_.case_LongArgumentU16;
    else
      ite = KRML_EABORT(uint16_t, "unreachable (pattern matches are exhaustive in F*)");
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out,
      pos_1 - (size_t)1U,
      (uint8_t)((uint32_t)ite / 256U));
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_1, lo);
    return pos_;
  }
  else if (xh1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_32_BITS)
  {
    size_t pos_ = res1 + (size_t)4U;
    uint32_t ite0;
    if (x2_.tag == CBOR_Spec_Raw_EverParse_LongArgumentU32)
      ite0 = x2_.case_LongArgumentU32;
    else
      ite0 = KRML_EABORT(uint32_t, "unreachable (pattern matches are exhaustive in F*)");
    uint8_t lo = (uint8_t)ite0;
    uint32_t ite;
    if (x2_.tag == CBOR_Spec_Raw_EverParse_LongArgumentU32)
      ite = x2_.case_LongArgumentU32;
    else
      ite = KRML_EABORT(uint32_t, "unreachable (pattern matches are exhaustive in F*)");
    uint32_t hi = ite / 256U;
    size_t pos_1 = pos_ - (size_t)1U;
    uint8_t lo1 = (uint8_t)hi;
    uint32_t hi1 = hi / 256U;
    size_t pos_2 = pos_1 - (size_t)1U;
    uint8_t lo2 = (uint8_t)hi1;
    size_t pos_3 = pos_2 - (size_t)1U;
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_3 - (size_t)1U, (uint8_t)(hi1 / 256U));
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_3, lo2);
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_2, lo1);
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_1, lo);
    return pos_;
  }
  else if (xh1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_64_BITS)
  {
    size_t pos_ = res1 + (size_t)8U;
    uint64_t ite0;
    if (x2_.tag == CBOR_Spec_Raw_EverParse_LongArgumentU64)
      ite0 = x2_.case_LongArgumentU64;
    else
      ite0 = KRML_EABORT(uint64_t, "unreachable (pattern matches are exhaustive in F*)");
    uint8_t lo = (uint8_t)ite0;
    uint64_t ite;
    if (x2_.tag == CBOR_Spec_Raw_EverParse_LongArgumentU64)
      ite = x2_.case_LongArgumentU64;
    else
      ite = KRML_EABORT(uint64_t, "unreachable (pattern matches are exhaustive in F*)");
    uint64_t hi = ite / 256ULL;
    size_t pos_1 = pos_ - (size_t)1U;
    uint8_t lo1 = (uint8_t)hi;
    uint64_t hi1 = hi / 256ULL;
    size_t pos_2 = pos_1 - (size_t)1U;
    uint8_t lo2 = (uint8_t)hi1;
    uint64_t hi2 = hi1 / 256ULL;
    size_t pos_3 = pos_2 - (size_t)1U;
    uint8_t lo3 = (uint8_t)hi2;
    uint64_t hi3 = hi2 / 256ULL;
    size_t pos_4 = pos_3 - (size_t)1U;
    uint8_t lo4 = (uint8_t)hi3;
    uint64_t hi4 = hi3 / 256ULL;
    size_t pos_5 = pos_4 - (size_t)1U;
    uint8_t lo5 = (uint8_t)hi4;
    uint64_t hi5 = hi4 / 256ULL;
    size_t pos_6 = pos_5 - (size_t)1U;
    uint8_t lo6 = (uint8_t)hi5;
    size_t pos_7 = pos_6 - (size_t)1U;
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_7 - (size_t)1U, (uint8_t)(hi5 / 256ULL));
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_7, lo6);
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_6, lo5);
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_5, lo4);
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_4, lo3);
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_3, lo2);
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_2, lo1);
    Pulse_Lib_Slice_op_Array_Assignment__uint8_t(out, pos_1, lo);
    return pos_;
  }
  else
    return res1;
}

static bool
CBOR_Pulse_Raw_Format_Serialize_size_header(CBOR_Spec_Raw_EverParse_header x, size_t *out)
{
  CBOR_Spec_Raw_EverParse_initial_byte_t
  xh1 =
    FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(x);
  size_t capacity = *out;
  bool ite;
  if (capacity < (size_t)1U)
    ite = false;
  else
  {
    *out = capacity - (size_t)1U;
    ite = true;
  }
  if (ite)
  {
    FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(x);
    if (xh1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_8_BITS)
    {
      size_t capacity = *out;
      if (capacity < (size_t)1U)
        return false;
      else
      {
        *out = capacity - (size_t)1U;
        return true;
      }
    }
    else if (xh1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_16_BITS)
    {
      size_t capacity = *out;
      if (capacity < (size_t)2U)
        return false;
      else
      {
        *out = capacity - (size_t)2U;
        return true;
      }
    }
    else if (xh1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_32_BITS)
    {
      size_t capacity = *out;
      if (capacity < (size_t)4U)
        return false;
      else
      {
        *out = capacity - (size_t)4U;
        return true;
      }
    }
    else if (xh1.additional_info == CBOR_SPEC_RAW_EVERPARSE_ADDITIONAL_INFO_LONG_ARGUMENT_64_BITS)
    {
      size_t capacity = *out;
      if (capacity < (size_t)8U)
        return false;
      else
      {
        *out = capacity - (size_t)8U;
        return true;
      }
    }
    else
      return true;
  }
  else
    return false;
}

static CBOR_Spec_Raw_EverParse_header
CBOR_Pulse_Raw_Format_Serialize_cbor_raw_get_header(cbor_raw xl)
{
  if (xl.tag == CBOR_Case_Int)
  {
    uint8_t ty;
    if (xl.tag == CBOR_Case_Int)
      ty = xl.case_CBOR_Case_Int.cbor_int_type;
    else
      ty = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (xl.tag == CBOR_Case_Int)
    {
      cbor_int c_ = xl.case_CBOR_Case_Int;
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = c_.cbor_int_size, .value = c_.cbor_int_value });
    }
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(ty, ite);
  }
  else if (xl.tag == CBOR_Case_String)
  {
    uint8_t ty;
    if (xl.tag == CBOR_Case_String)
      ty = xl.case_CBOR_Case_String.cbor_string_type;
    else
      ty = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (xl.tag == CBOR_Case_String)
    {
      cbor_string c_ = xl.case_CBOR_Case_String;
      ite =
        (
          (CBOR_Spec_Raw_Base_raw_uint64){
            .size = c_.cbor_string_size,
            .value = (uint64_t)Pulse_Lib_Slice_len__uint8_t(c_.cbor_string_ptr)
          }
        );
    }
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(ty, ite);
  }
  else if (xl.tag == CBOR_Case_Tagged)
  {
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (xl.tag == CBOR_Case_Tagged)
      ite = xl.case_CBOR_Case_Tagged.cbor_tagged_tag;
    else if (xl.tag == CBOR_Case_Serialized_Tagged)
      ite = xl.case_CBOR_Case_Serialized_Tagged.cbor_serialized_header;
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(CBOR_MAJOR_TYPE_TAGGED, ite);
  }
  else if (xl.tag == CBOR_Case_Serialized_Tagged)
  {
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (xl.tag == CBOR_Case_Tagged)
      ite = xl.case_CBOR_Case_Tagged.cbor_tagged_tag;
    else if (xl.tag == CBOR_Case_Serialized_Tagged)
      ite = xl.case_CBOR_Case_Serialized_Tagged.cbor_serialized_header;
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(CBOR_MAJOR_TYPE_TAGGED, ite);
  }
  else if (xl.tag == CBOR_Case_Array)
  {
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (xl.tag == CBOR_Case_Array)
    {
      cbor_array c_ = xl.case_CBOR_Case_Array;
      ite =
        (
          (CBOR_Spec_Raw_Base_raw_uint64){
            .size = c_.cbor_array_length_size,
            .value = (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(c_.cbor_array_ptr)
          }
        );
    }
    else if (xl.tag == CBOR_Case_Serialized_Array)
      ite = xl.case_CBOR_Case_Serialized_Array.cbor_serialized_header;
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(CBOR_MAJOR_TYPE_ARRAY, ite);
  }
  else if (xl.tag == CBOR_Case_Serialized_Array)
  {
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (xl.tag == CBOR_Case_Array)
    {
      cbor_array c_ = xl.case_CBOR_Case_Array;
      ite =
        (
          (CBOR_Spec_Raw_Base_raw_uint64){
            .size = c_.cbor_array_length_size,
            .value = (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(c_.cbor_array_ptr)
          }
        );
    }
    else if (xl.tag == CBOR_Case_Serialized_Array)
      ite = xl.case_CBOR_Case_Serialized_Array.cbor_serialized_header;
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(CBOR_MAJOR_TYPE_ARRAY, ite);
  }
  else if (xl.tag == CBOR_Case_Map)
  {
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (xl.tag == CBOR_Case_Map)
    {
      cbor_map c_ = xl.case_CBOR_Case_Map;
      ite =
        (
          (CBOR_Spec_Raw_Base_raw_uint64){
            .size = c_.cbor_map_length_size,
            .value = (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(c_.cbor_map_ptr)
          }
        );
    }
    else if (xl.tag == CBOR_Case_Serialized_Map)
      ite = xl.case_CBOR_Case_Serialized_Map.cbor_serialized_header;
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(CBOR_MAJOR_TYPE_MAP, ite);
  }
  else if (xl.tag == CBOR_Case_Serialized_Map)
  {
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (xl.tag == CBOR_Case_Map)
    {
      cbor_map c_ = xl.case_CBOR_Case_Map;
      ite =
        (
          (CBOR_Spec_Raw_Base_raw_uint64){
            .size = c_.cbor_map_length_size,
            .value = (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(c_.cbor_map_ptr)
          }
        );
    }
    else if (xl.tag == CBOR_Case_Serialized_Map)
      ite = xl.case_CBOR_Case_Serialized_Map.cbor_serialized_header;
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_raw_uint64_as_argument(CBOR_MAJOR_TYPE_MAP, ite);
  }
  else if (xl.tag == CBOR_Case_Simple)
  {
    uint8_t ite;
    if (xl.tag == CBOR_Case_Simple)
      ite = xl.case_CBOR_Case_Simple;
    else
      ite = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Spec_Raw_EverParse_simple_value_as_argument(ite);
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static CBOR_Spec_Raw_EverParse_header
CBOR_Pulse_Raw_Format_Serialize_cbor_raw_with_perm_get_header(cbor_raw xl)
{
  return CBOR_Pulse_Raw_Format_Serialize_cbor_raw_get_header(xl);
}

static void
Pulse_Lib_Slice_copy__uint8_t(
  Pulse_Lib_Slice_slice__uint8_t dst,
  Pulse_Lib_Slice_slice__uint8_t src
)
{
  memcpy(dst.elt, src.elt, src.len * sizeof (uint8_t));
}

typedef struct
FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_s
{
  FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_tags
  tag;
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw v;
}
FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw;

typedef struct
FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry_s
{
  FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_tags
  tag;
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry v;
}
FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry;

size_t
CBOR_Pulse_Raw_Format_Serialize_ser_(
  cbor_raw x_,
  Pulse_Lib_Slice_slice__uint8_t out,
  size_t offset
)
{
  CBOR_Spec_Raw_EverParse_header
  xh1 = CBOR_Pulse_Raw_Format_Serialize_cbor_raw_with_perm_get_header(x_);
  size_t res1 = CBOR_Pulse_Raw_Format_Serialize_write_header(xh1, out, offset);
  CBOR_Spec_Raw_EverParse_initial_byte_t b = xh1.fst;
  if (b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING || b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING)
  {
    cbor_raw scrut = x_;
    Pulse_Lib_Slice_slice__uint8_t x2_;
    if (scrut.tag == CBOR_Case_String)
      x2_ = scrut.case_CBOR_Case_String.cbor_string_ptr;
    else
      x2_ =
        KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
          "unreachable (pattern matches are exhaustive in F*)");
    size_t length = Pulse_Lib_Slice_len__uint8_t(x2_);
    Pulse_Lib_Slice_copy__uint8_t(Pulse_Lib_Slice_split__uint8_t(Pulse_Lib_Slice_split__uint8_t(out,
          res1).snd,
        length).fst,
      x2_);
    return res1 + length;
  }
  else if (xh1.fst.major_type == CBOR_MAJOR_TYPE_ARRAY)
  {
    bool ite;
    if (x_.tag == CBOR_Case_Array)
      ite = true;
    else
      ite = false;
    if (ite)
    {
      cbor_raw scrut0 = x_;
      FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw
      scrut;
      if (scrut0.tag == CBOR_Case_Array)
        scrut =
          (
            (FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw){
              .tag = FStar_Pervasives_Native_Some,
              .v = scrut0.case_CBOR_Case_Array.cbor_array_ptr
            }
          );
      else
        scrut =
          (
            (FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw){
              .tag = FStar_Pervasives_Native_None
            }
          );
      Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw a;
      if (scrut.tag == FStar_Pervasives_Native_Some)
        a = scrut.v;
      else
        a =
          KRML_EABORT(Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw,
            "unreachable (pattern matches are exhaustive in F*)");
      size_t pres = res1;
      size_t pi = (size_t)0U;
      size_t i0 = pi;
      bool cond = i0 < (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(xh1.fst, xh1.snd);
      while (cond)
      {
        size_t i = pi;
        size_t off = pres;
        size_t i_ = i + (size_t)1U;
        size_t
        res =
          CBOR_Pulse_Raw_Format_Serialize_ser_(Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_raw(a,
              i),
            out,
            off);
        pi = i_;
        pres = res;
        size_t i0 = pi;
        cond = i0 < (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(xh1.fst, xh1.snd);
      }
      return pres;
    }
    else
    {
      cbor_raw scrut = x_;
      Pulse_Lib_Slice_slice__uint8_t x2_;
      if (scrut.tag == CBOR_Case_Serialized_Array)
        x2_ = scrut.case_CBOR_Case_Serialized_Array.cbor_serialized_payload;
      else
        x2_ =
          KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
            "unreachable (pattern matches are exhaustive in F*)");
      size_t length = Pulse_Lib_Slice_len__uint8_t(x2_);
      Pulse_Lib_Slice_copy__uint8_t(Pulse_Lib_Slice_split__uint8_t(Pulse_Lib_Slice_split__uint8_t(out,
            res1).snd,
          length).fst,
        x2_);
      return res1 + length;
    }
  }
  else if (xh1.fst.major_type == CBOR_MAJOR_TYPE_MAP)
  {
    bool ite;
    if (x_.tag == CBOR_Case_Map)
      ite = true;
    else
      ite = false;
    if (ite)
    {
      cbor_raw scrut0 = x_;
      FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry
      scrut;
      if (scrut0.tag == CBOR_Case_Map)
        scrut =
          (
            (FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry){
              .tag = FStar_Pervasives_Native_Some,
              .v = scrut0.case_CBOR_Case_Map.cbor_map_ptr
            }
          );
      else
        scrut =
          (
            (FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry){
              .tag = FStar_Pervasives_Native_None
            }
          );
      Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry a;
      if (scrut.tag == FStar_Pervasives_Native_Some)
        a = scrut.v;
      else
        a =
          KRML_EABORT(Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry,
            "unreachable (pattern matches are exhaustive in F*)");
      size_t pres = res1;
      size_t pi = (size_t)0U;
      size_t i0 = pi;
      bool cond = i0 < (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(xh1.fst, xh1.snd);
      while (cond)
      {
        size_t i = pi;
        size_t off = pres;
        cbor_map_entry
        e = Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_map_entry(a, i);
        size_t i_ = i + (size_t)1U;
        size_t
        res =
          CBOR_Pulse_Raw_Format_Serialize_ser_(e.cbor_map_entry_value,
            out,
            CBOR_Pulse_Raw_Format_Serialize_ser_(e.cbor_map_entry_key, out, off));
        pi = i_;
        pres = res;
        size_t i0 = pi;
        cond = i0 < (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(xh1.fst, xh1.snd);
      }
      return pres;
    }
    else
    {
      cbor_raw scrut = x_;
      Pulse_Lib_Slice_slice__uint8_t x2_;
      if (scrut.tag == CBOR_Case_Serialized_Map)
        x2_ = scrut.case_CBOR_Case_Serialized_Map.cbor_serialized_payload;
      else
        x2_ =
          KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
            "unreachable (pattern matches are exhaustive in F*)");
      size_t length = Pulse_Lib_Slice_len__uint8_t(x2_);
      Pulse_Lib_Slice_copy__uint8_t(Pulse_Lib_Slice_split__uint8_t(Pulse_Lib_Slice_split__uint8_t(out,
            res1).snd,
          length).fst,
        x2_);
      return res1 + length;
    }
  }
  else if (xh1.fst.major_type == CBOR_MAJOR_TYPE_TAGGED)
  {
    bool ite0;
    if (x_.tag == CBOR_Case_Tagged)
      ite0 = true;
    else
      ite0 = false;
    if (ite0)
    {
      cbor_raw scrut = x_;
      cbor_raw ite;
      if (scrut.tag == CBOR_Case_Tagged)
        ite = *scrut.case_CBOR_Case_Tagged.cbor_tagged_ptr;
      else
        ite = KRML_EABORT(cbor_raw, "unreachable (pattern matches are exhaustive in F*)");
      return CBOR_Pulse_Raw_Format_Serialize_ser_(ite, out, res1);
    }
    else
    {
      cbor_raw scrut = x_;
      Pulse_Lib_Slice_slice__uint8_t x2_;
      if (scrut.tag == CBOR_Case_Serialized_Tagged)
        x2_ = scrut.case_CBOR_Case_Serialized_Tagged.cbor_serialized_payload;
      else
        x2_ =
          KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
            "unreachable (pattern matches are exhaustive in F*)");
      size_t length = Pulse_Lib_Slice_len__uint8_t(x2_);
      Pulse_Lib_Slice_copy__uint8_t(Pulse_Lib_Slice_split__uint8_t(Pulse_Lib_Slice_split__uint8_t(out,
            res1).snd,
          length).fst,
        x2_);
      return res1 + length;
    }
  }
  else
    return res1;
}

static size_t
CBOR_Pulse_Raw_Format_Serialize_ser(
  cbor_raw x1_,
  Pulse_Lib_Slice_slice__uint8_t out,
  size_t offset
)
{
  return CBOR_Pulse_Raw_Format_Serialize_ser_(x1_, out, offset);
}

static size_t
CBOR_Pulse_Raw_Format_Serialize_cbor_serialize(
  cbor_raw x,
  Pulse_Lib_Slice_slice__uint8_t output
)
{
  return CBOR_Pulse_Raw_Format_Serialize_ser(x, output, (size_t)0U);
}

bool CBOR_Pulse_Raw_Format_Serialize_siz_(cbor_raw x_, size_t *out)
{
  CBOR_Spec_Raw_EverParse_header
  xh1 = CBOR_Pulse_Raw_Format_Serialize_cbor_raw_with_perm_get_header(x_);
  if (CBOR_Pulse_Raw_Format_Serialize_size_header(xh1, out))
  {
    CBOR_Spec_Raw_EverParse_initial_byte_t b = xh1.fst;
    if (b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING || b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING)
    {
      cbor_raw scrut = x_;
      Pulse_Lib_Slice_slice__uint8_t ite;
      if (scrut.tag == CBOR_Case_String)
        ite = scrut.case_CBOR_Case_String.cbor_string_ptr;
      else
        ite =
          KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
            "unreachable (pattern matches are exhaustive in F*)");
      size_t length = Pulse_Lib_Slice_len__uint8_t(ite);
      size_t cur = *out;
      if (cur < length)
        return false;
      else
      {
        *out = cur - length;
        return true;
      }
    }
    else if (xh1.fst.major_type == CBOR_MAJOR_TYPE_ARRAY)
    {
      bool ite0;
      if (x_.tag == CBOR_Case_Array)
        ite0 = true;
      else
        ite0 = false;
      if (ite0)
      {
        cbor_raw scrut0 = x_;
        FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw
        scrut;
        if (scrut0.tag == CBOR_Case_Array)
          scrut =
            (
              (FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw){
                .tag = FStar_Pervasives_Native_Some,
                .v = scrut0.case_CBOR_Case_Array.cbor_array_ptr
              }
            );
        else
          scrut =
            (
              (FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw){
                .tag = FStar_Pervasives_Native_None
              }
            );
        Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw a;
        if (scrut.tag == FStar_Pervasives_Native_Some)
          a = scrut.v;
        else
          a =
            KRML_EABORT(Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw,
              "unreachable (pattern matches are exhaustive in F*)");
        bool pres = true;
        size_t pi = (size_t)0U;
        bool res = pres;
        size_t i0 = pi;
        bool
        cond = res && i0 < (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(xh1.fst, xh1.snd);
        while (cond)
        {
          size_t i0 = pi;
          if
          (
            CBOR_Pulse_Raw_Format_Serialize_siz_(Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_raw(a,
                i0),
              out)
          )
            pi = i0 + (size_t)1U;
          else
            pres = false;
          bool res = pres;
          size_t i = pi;
          cond = res && i < (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(xh1.fst, xh1.snd);
        }
        return pres;
      }
      else
      {
        cbor_raw scrut = x_;
        Pulse_Lib_Slice_slice__uint8_t ite;
        if (scrut.tag == CBOR_Case_Serialized_Array)
          ite = scrut.case_CBOR_Case_Serialized_Array.cbor_serialized_payload;
        else
          ite =
            KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
              "unreachable (pattern matches are exhaustive in F*)");
        size_t length = Pulse_Lib_Slice_len__uint8_t(ite);
        size_t cur = *out;
        if (cur < length)
          return false;
        else
        {
          *out = cur - length;
          return true;
        }
      }
    }
    else if (xh1.fst.major_type == CBOR_MAJOR_TYPE_MAP)
    {
      bool ite0;
      if (x_.tag == CBOR_Case_Map)
        ite0 = true;
      else
        ite0 = false;
      if (ite0)
      {
        cbor_raw scrut0 = x_;
        FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry
        scrut;
        if (scrut0.tag == CBOR_Case_Map)
          scrut =
            (
              (FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry){
                .tag = FStar_Pervasives_Native_Some,
                .v = scrut0.case_CBOR_Case_Map.cbor_map_ptr
              }
            );
        else
          scrut =
            (
              (FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_map_entry){
                .tag = FStar_Pervasives_Native_None
              }
            );
        Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry a;
        if (scrut.tag == FStar_Pervasives_Native_Some)
          a = scrut.v;
        else
          a =
            KRML_EABORT(Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry,
              "unreachable (pattern matches are exhaustive in F*)");
        bool pres = true;
        size_t pi = (size_t)0U;
        bool res = pres;
        size_t i0 = pi;
        bool
        cond = res && i0 < (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(xh1.fst, xh1.snd);
        while (cond)
        {
          size_t i0 = pi;
          cbor_map_entry
          e = Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_map_entry(a, i0);
          bool ite;
          if (CBOR_Pulse_Raw_Format_Serialize_siz_(e.cbor_map_entry_key, out))
            ite = CBOR_Pulse_Raw_Format_Serialize_siz_(e.cbor_map_entry_value, out);
          else
            ite = false;
          if (ite)
            pi = i0 + (size_t)1U;
          else
            pres = false;
          bool res = pres;
          size_t i = pi;
          cond = res && i < (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(xh1.fst, xh1.snd);
        }
        return pres;
      }
      else
      {
        cbor_raw scrut = x_;
        Pulse_Lib_Slice_slice__uint8_t ite;
        if (scrut.tag == CBOR_Case_Serialized_Map)
          ite = scrut.case_CBOR_Case_Serialized_Map.cbor_serialized_payload;
        else
          ite =
            KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
              "unreachable (pattern matches are exhaustive in F*)");
        size_t length = Pulse_Lib_Slice_len__uint8_t(ite);
        size_t cur = *out;
        if (cur < length)
          return false;
        else
        {
          *out = cur - length;
          return true;
        }
      }
    }
    else if (xh1.fst.major_type == CBOR_MAJOR_TYPE_TAGGED)
    {
      bool ite0;
      if (x_.tag == CBOR_Case_Tagged)
        ite0 = true;
      else
        ite0 = false;
      if (ite0)
      {
        cbor_raw scrut = x_;
        cbor_raw ite;
        if (scrut.tag == CBOR_Case_Tagged)
          ite = *scrut.case_CBOR_Case_Tagged.cbor_tagged_ptr;
        else
          ite = KRML_EABORT(cbor_raw, "unreachable (pattern matches are exhaustive in F*)");
        return CBOR_Pulse_Raw_Format_Serialize_siz_(ite, out);
      }
      else
      {
        cbor_raw scrut = x_;
        Pulse_Lib_Slice_slice__uint8_t ite;
        if (scrut.tag == CBOR_Case_Serialized_Tagged)
          ite = scrut.case_CBOR_Case_Serialized_Tagged.cbor_serialized_payload;
        else
          ite =
            KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
              "unreachable (pattern matches are exhaustive in F*)");
        size_t length = Pulse_Lib_Slice_len__uint8_t(ite);
        size_t cur = *out;
        if (cur < length)
          return false;
        else
        {
          *out = cur - length;
          return true;
        }
      }
    }
    else
      return true;
  }
  else
    return false;
}

static bool CBOR_Pulse_Raw_Format_Serialize_siz(cbor_raw x1_, size_t *out)
{
  return CBOR_Pulse_Raw_Format_Serialize_siz_(x1_, out);
}

static size_t CBOR_Pulse_Raw_Format_Serialize_cbor_size(cbor_raw x, size_t bound)
{
  size_t output = bound;
  if (CBOR_Pulse_Raw_Format_Serialize_siz(x, &output))
    return bound - output;
  else
    return (size_t)0U;
}

static uint8_t CBOR_Pulse_Raw_Compare_impl_major_type(cbor_raw x)
{
  if (x.tag == CBOR_Case_Simple)
    return CBOR_MAJOR_TYPE_SIMPLE_VALUE;
  else if (x.tag == CBOR_Case_Int)
    if (x.tag == CBOR_Case_Int)
      return x.case_CBOR_Case_Int.cbor_int_type;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  else if (x.tag == CBOR_Case_String)
    if (x.tag == CBOR_Case_String)
      return x.case_CBOR_Case_String.cbor_string_type;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  else if (x.tag == CBOR_Case_Tagged)
    return CBOR_MAJOR_TYPE_TAGGED;
  else if (x.tag == CBOR_Case_Serialized_Tagged)
    return CBOR_MAJOR_TYPE_TAGGED;
  else if (x.tag == CBOR_Case_Array)
    return CBOR_MAJOR_TYPE_ARRAY;
  else if (x.tag == CBOR_Case_Serialized_Array)
    return CBOR_MAJOR_TYPE_ARRAY;
  else if (x.tag == CBOR_Case_Map)
    return CBOR_MAJOR_TYPE_MAP;
  else if (x.tag == CBOR_Case_Serialized_Map)
    return CBOR_MAJOR_TYPE_MAP;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

bool
CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth_aux(
  size_t bound,
  Pulse_Lib_Slice_slice__uint8_t *pl,
  size_t n1
)
{
  size_t pn = n1;
  bool pres = true;
  while (pres && pn > (size_t)0U)
  {
    Pulse_Lib_Slice_slice__uint8_t l = *pl;
    size_t n_ = pn - (size_t)1U;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut =
      Pulse_Lib_Slice_split__uint8_t(l,
        CBOR_Pulse_Raw_EverParse_Format_jump_header(l, (size_t)0U));
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
    Pulse_Lib_Slice_slice__uint8_t tl_ = scrut3.snd;
    CBOR_Spec_Raw_EverParse_header h = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut3.fst);
    CBOR_Spec_Raw_EverParse_initial_byte_t b = h.fst;
    size_t ite;
    if (b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING || b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING)
      ite = (size_t)0U + (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h.fst, h.snd);
    else
      ite = (size_t)0U;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut4 = Pulse_Lib_Slice_split__uint8_t(tl_, ite);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut5 = { .fst = scrut4.fst, .snd = scrut4.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
    Pulse_Lib_Slice_slice__uint8_t
    tl =
      (
        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
          .fst = scrut7.fst,
          .snd = scrut7.snd
        }
      ).snd;
    uint8_t m = CBOR_Spec_Raw_EverParse_get_header_major_type(h);
    if (m == CBOR_MAJOR_TYPE_TAGGED)
      *pl = tl;
    else if (m == CBOR_MAJOR_TYPE_ARRAY)
    {
      *pl = tl;
      pn =
        (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h),
          FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h))
        + n_;
    }
    else if (m == CBOR_MAJOR_TYPE_MAP)
      if (bound == (size_t)0U)
        pres = false;
      else
      {
        *pl = tl;
        size_t
        npairs =
          (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h),
            FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h));
        if
        (
          CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth_aux(bound - (size_t)1U,
            pl,
            npairs + npairs)
        )
          pn = n_;
        else
          pres = false;
      }
    else
    {
      *pl = tl;
      pn = n_;
    }
  }
  return pres;
}

static bool
CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth(
  size_t bound,
  size_t n0,
  Pulse_Lib_Slice_slice__uint8_t l0
)
{
  Pulse_Lib_Slice_slice__uint8_t buf = l0;
  return CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth_aux(bound, &buf, n0);
}

static bool
FStar_Pervasives_Native_uu___is_None__size_t(FStar_Pervasives_Native_option__size_t projectee)
{
  if (projectee.tag == FStar_Pervasives_Native_None)
    return true;
  else
    return false;
}

static bool
CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth_opt(
  FStar_Pervasives_Native_option__size_t bound,
  size_t n0,
  Pulse_Lib_Slice_slice__uint8_t l0
)
{
  if (FStar_Pervasives_Native_uu___is_None__size_t(bound))
    return true;
  else
  {
    size_t ite;
    if (bound.tag == FStar_Pervasives_Native_Some)
      ite = bound.v;
    else
      ite = KRML_EABORT(size_t, "unreachable (pattern matches are exhaustive in F*)");
    return CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth(ite, n0, l0);
  }
}

static bool
FStar_Pervasives_Native_uu___is_None__bool(FStar_Pervasives_Native_option__bool projectee)
{
  if (projectee.tag == FStar_Pervasives_Native_None)
    return true;
  else
    return false;
}

bool
__eq__FStar_Pervasives_Native_option__size_t(
  FStar_Pervasives_Native_option__size_t y,
  FStar_Pervasives_Native_option__size_t x
)
{
  if (x.tag == FStar_Pervasives_Native_None)
    if (y.tag == FStar_Pervasives_Native_None)
      return true;
    else
      return false;
  else if (x.tag == FStar_Pervasives_Native_Some)
  {
    size_t x_v = x.v;
    if (y.tag == FStar_Pervasives_Native_Some)
      return true && y.v == x_v;
    else
      return false;
  }
  else
    return false;
}

bool
__eq__FStar_Pervasives_Native_option__bool(
  FStar_Pervasives_Native_option__bool y,
  FStar_Pervasives_Native_option__bool x
)
{
  if (x.tag == FStar_Pervasives_Native_None)
    if (y.tag == FStar_Pervasives_Native_None)
      return true;
    else
      return false;
  else if (x.tag == FStar_Pervasives_Native_Some)
  {
    bool x_v = x.v;
    if (y.tag == FStar_Pervasives_Native_Some)
      return true && y.v == x_v;
    else
      return false;
  }
  else
    return false;
}

FStar_Pervasives_Native_option__bool
CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_map_hd_basic(
  FStar_Pervasives_Native_option__size_t map_bound,
  Pulse_Lib_Slice_slice__uint8_t l1,
  Pulse_Lib_Slice_slice__uint8_t l2
)
{
  if (false)
    return
      ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true });
  else
  {
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 =
      Pulse_Lib_Slice_split__uint8_t(l1,
        CBOR_Pulse_Raw_EverParse_Format_jump_header(l1, (size_t)0U));
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
    CBOR_Spec_Raw_EverParse_header
    h1 =
      CBOR_Pulse_Raw_EverParse_Format_read_header((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut2.fst,
            .snd = scrut2.snd
          }
        ).fst);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut3 =
      Pulse_Lib_Slice_split__uint8_t(l2,
        CBOR_Pulse_Raw_EverParse_Format_jump_header(l2, (size_t)0U));
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut5 = { .fst = scrut4.fst, .snd = scrut4.snd };
    CBOR_Spec_Raw_EverParse_header
    h2 =
      CBOR_Pulse_Raw_EverParse_Format_read_header((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut5.fst,
            .snd = scrut5.snd
          }
        ).fst);
    uint8_t mt1 = CBOR_Spec_Raw_EverParse_get_header_major_type(h1);
    if
    (
      mt1 == CBOR_MAJOR_TYPE_MAP &&
        CBOR_Spec_Raw_EverParse_get_header_major_type(h2) == CBOR_MAJOR_TYPE_MAP
    )
      if
      (
        __eq__FStar_Pervasives_Native_option__size_t(map_bound,
          (
            (FStar_Pervasives_Native_option__size_t){
              .tag = FStar_Pervasives_Native_Some,
              .v = (size_t)0U
            }
          ))
      )
        return ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_None });
      else
      {
        FStar_Pervasives_Native_option__size_t map_bound_;
        if (map_bound.tag == FStar_Pervasives_Native_None)
          map_bound_ =
            ((FStar_Pervasives_Native_option__size_t){ .tag = FStar_Pervasives_Native_None });
        else if (map_bound.tag == FStar_Pervasives_Native_Some)
          map_bound_ =
            (
              (FStar_Pervasives_Native_option__size_t){
                .tag = FStar_Pervasives_Native_Some,
                .v = map_bound.v - (size_t)1U
              }
            );
        else
          map_bound_ =
            KRML_EABORT(FStar_Pervasives_Native_option__size_t,
              "unreachable (pattern matches are exhaustive in F*)");
        size_t
        nv1 =
          (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h1),
            FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h1));
        size_t
        nv2 =
          (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h2),
            FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h2));
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut0 =
          Pulse_Lib_Slice_split__uint8_t(l1,
            CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l1, (size_t)0U));
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
        Pulse_Lib_Slice_slice__uint8_t
        map1 =
          (
            (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
              .fst = scrut2.fst,
              .snd = scrut2.snd
            }
          ).fst;
        CBOR_Spec_Raw_EverParse_header ph = h1;
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut3 =
          Pulse_Lib_Slice_split__uint8_t(map1,
            CBOR_Pulse_Raw_EverParse_Format_jump_header(map1, (size_t)0U));
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut5 = { .fst = scrut4.fst, .snd = scrut4.snd };
        Pulse_Lib_Slice_slice__uint8_t outc0 = scrut5.snd;
        ph = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut5.fst);
        Pulse_Lib_Slice_slice__uint8_t c1 = outc0;
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut6 =
          Pulse_Lib_Slice_split__uint8_t(l2,
            CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l2, (size_t)0U));
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
        Pulse_Lib_Slice_slice__uint8_t
        map2 =
          (
            (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
              .fst = scrut8.fst,
              .snd = scrut8.snd
            }
          ).fst;
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut9 =
          Pulse_Lib_Slice_split__uint8_t(map2,
            CBOR_Pulse_Raw_EverParse_Format_jump_header(map2, (size_t)0U));
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut10 = { .fst = scrut9.fst, .snd = scrut9.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut11 = { .fst = scrut10.fst, .snd = scrut10.snd };
        Pulse_Lib_Slice_slice__uint8_t outc = scrut11.snd;
        ph = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut11.fst);
        Pulse_Lib_Slice_slice__uint8_t c2 = outc;
        Pulse_Lib_Slice_slice__uint8_t pl = c1;
        size_t pn0 = nv1;
        FStar_Pervasives_Native_option__bool
        pres0 = { .tag = FStar_Pervasives_Native_Some, .v = true };
        size_t n0 = pn0;
        bool
        cond =
          n0 > (size_t)0U &&
            __eq__FStar_Pervasives_Native_option__bool(pres0,
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = true
                }
              ));
        while (cond)
        {
          Pulse_Lib_Slice_slice__uint8_t l = pl;
          size_t n_ = pn0 - (size_t)1U;
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut0 =
            Pulse_Lib_Slice_split__uint8_t(l,
              CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l, (size_t)0U));
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
          Pulse_Lib_Slice_slice__uint8_t lh = scrut4.fst;
          Pulse_Lib_Slice_slice__uint8_t lt = scrut4.snd;
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut5 =
            Pulse_Lib_Slice_split__uint8_t(lt,
              CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(lt, (size_t)0U));
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
          Pulse_Lib_Slice_slice__uint8_t lv = scrut9.fst;
          Pulse_Lib_Slice_slice__uint8_t lt_ = scrut9.snd;
          Pulse_Lib_Slice_slice__uint8_t pll = c2;
          size_t pn1 = nv2;
          FStar_Pervasives_Native_option__bool
          pres1 = { .tag = FStar_Pervasives_Native_Some, .v = false };
          bool pcont = true;
          size_t n3 = pn1;
          bool cont0 = pcont;
          bool
          cond0 =
            n3 > (size_t)0U &&
              __eq__FStar_Pervasives_Native_option__bool(pres1,
                (
                  (FStar_Pervasives_Native_option__bool){
                    .tag = FStar_Pervasives_Native_Some,
                    .v = false
                  }
                ))
            && cont0;
          while (cond0)
          {
            Pulse_Lib_Slice_slice__uint8_t l3 = pll;
            size_t n_1 = pn1 - (size_t)1U;
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut0 =
              Pulse_Lib_Slice_split__uint8_t(l3,
                CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l3, (size_t)0U));
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
            Pulse_Lib_Slice_slice__uint8_t lt1 = scrut4.snd;
            size_t pn2 = (size_t)1U;
            Pulse_Lib_Slice_slice__uint8_t pl10 = lh;
            Pulse_Lib_Slice_slice__uint8_t pl20 = scrut4.fst;
            FStar_Pervasives_Native_option__bool
            pres20 = { .tag = FStar_Pervasives_Native_Some, .v = true };
            size_t n40 = pn2;
            bool
            cond =
              __eq__FStar_Pervasives_Native_option__bool(pres20,
                (
                  (FStar_Pervasives_Native_option__bool){
                    .tag = FStar_Pervasives_Native_Some,
                    .v = true
                  }
                ))
              && n40 > (size_t)0U;
            while (cond)
            {
              Pulse_Lib_Slice_slice__uint8_t l1_ = pl10;
              Pulse_Lib_Slice_slice__uint8_t l2_ = pl20;
              FStar_Pervasives_Native_option__bool
              r =
                CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_map_hd_basic(map_bound_,
                  l1_,
                  l2_);
              if (FStar_Pervasives_Native_uu___is_None__bool(r))
                pres20 = r;
              else
              {
                size_t n4 = pn2;
                if
                (
                  __eq__FStar_Pervasives_Native_option__bool(r,
                    (
                      (FStar_Pervasives_Native_option__bool){
                        .tag = FStar_Pervasives_Native_Some,
                        .v = true
                      }
                    ))
                )
                {
                  size_t n_2 = n4 - (size_t)1U;
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut0 =
                    Pulse_Lib_Slice_split__uint8_t(l1_,
                      CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l1_, (size_t)0U));
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                  Pulse_Lib_Slice_slice__uint8_t
                  tl1 =
                    (
                      (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                        .fst = scrut2.fst,
                        .snd = scrut2.snd
                      }
                    ).snd;
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut =
                    Pulse_Lib_Slice_split__uint8_t(l2_,
                      CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l2_, (size_t)0U));
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut3 = { .fst = scrut.fst, .snd = scrut.snd };
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                  Pulse_Lib_Slice_slice__uint8_t
                  tl2 =
                    (
                      (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                        .fst = scrut4.fst,
                        .snd = scrut4.snd
                      }
                    ).snd;
                  pn2 = n_2;
                  pl10 = tl1;
                  pl20 = tl2;
                }
                else
                {
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut0 =
                    Pulse_Lib_Slice_split__uint8_t(l1_,
                      CBOR_Pulse_Raw_EverParse_Format_jump_header(l1_, (size_t)0U));
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                  Pulse_Lib_Slice_slice__uint8_t tl1 = scrut4.snd;
                  CBOR_Spec_Raw_EverParse_header
                  h11 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut4.fst);
                  uint8_t mt11 = CBOR_Spec_Raw_EverParse_get_header_major_type(h11);
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut5 =
                    Pulse_Lib_Slice_split__uint8_t(l2_,
                      CBOR_Pulse_Raw_EverParse_Format_jump_header(l2_, (size_t)0U));
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
                  K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                  scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
                  Pulse_Lib_Slice_slice__uint8_t tl2 = scrut9.snd;
                  CBOR_Spec_Raw_EverParse_header
                  h21 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut9.fst);
                  if (mt11 != CBOR_Spec_Raw_EverParse_get_header_major_type(h21))
                    pres20 =
                      (
                        (FStar_Pervasives_Native_option__bool){
                          .tag = FStar_Pervasives_Native_Some,
                          .v = false
                        }
                      );
                  else
                  {
                    CBOR_Spec_Raw_EverParse_initial_byte_t b0 = h11.fst;
                    size_t ite0;
                    if
                    (
                      b0.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                        b0.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
                    )
                      ite0 =
                        (size_t)0U +
                          (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h11.fst, h11.snd);
                    else
                      ite0 = (size_t)0U;
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut0 = Pulse_Lib_Slice_split__uint8_t(tl1, ite0);
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                    Pulse_Lib_Slice_slice__uint8_t lc1 = scrut4.fst;
                    Pulse_Lib_Slice_slice__uint8_t tl1_ = scrut4.snd;
                    size_t
                    n_2 =
                      CBOR_Pulse_Raw_EverParse_Format_impl_remaining_data_items_header(h11) +
                        n4 - (size_t)1U;
                    CBOR_Spec_Raw_EverParse_initial_byte_t b = h21.fst;
                    size_t ite1;
                    if
                    (
                      b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                        b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
                    )
                      ite1 =
                        (size_t)0U +
                          (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h21.fst, h21.snd);
                    else
                      ite1 = (size_t)0U;
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut5 = Pulse_Lib_Slice_split__uint8_t(tl2, ite1);
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
                    Pulse_Lib_Slice_slice__uint8_t lc2 = scrut9.fst;
                    Pulse_Lib_Slice_slice__uint8_t tl2_ = scrut9.snd;
                    uint8_t mt12 = CBOR_Spec_Raw_EverParse_get_header_major_type(h11);
                    bool ite2;
                    if (mt12 == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
                    {
                      CBOR_Spec_Raw_EverParse_long_argument
                      scrut0 =
                        FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11);
                      uint8_t ite0;
                      if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                        ite0 =
                          FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11).additional_info;
                      else if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                        ite0 = scrut0.case_LongArgumentSimpleValue;
                      else
                        ite0 =
                          KRML_EABORT(uint8_t,
                            "unreachable (pattern matches are exhaustive in F*)");
                      CBOR_Spec_Raw_EverParse_long_argument
                      scrut =
                        FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21);
                      uint8_t ite;
                      if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                        ite =
                          FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21).additional_info;
                      else if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                        ite = scrut.case_LongArgumentSimpleValue;
                      else
                        ite =
                          KRML_EABORT(uint8_t,
                            "unreachable (pattern matches are exhaustive in F*)");
                      ite2 = ite0 == ite;
                    }
                    else
                    {
                      uint64_t
                      len =
                        CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11),
                          FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11));
                      if
                      (
                        len !=
                          CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21),
                            FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21))
                      )
                        ite2 = false;
                      else if
                      (mt12 == CBOR_MAJOR_TYPE_BYTE_STRING || mt12 == CBOR_MAJOR_TYPE_TEXT_STRING)
                        ite2 =
                          CBOR_Pulse_Raw_Compare_Bytes_lex_compare_bytes(lc1, lc2) == (int16_t)0;
                      else
                        ite2 = mt12 != CBOR_MAJOR_TYPE_MAP;
                    }
                    if (ite2)
                    {
                      pn2 = n_2;
                      pl10 = tl1_;
                      pl20 = tl2_;
                    }
                    else
                      pres20 =
                        (
                          (FStar_Pervasives_Native_option__bool){
                            .tag = FStar_Pervasives_Native_Some,
                            .v = false
                          }
                        );
                  }
                }
              }
              size_t n4 = pn2;
              cond =
                __eq__FStar_Pervasives_Native_option__bool(pres20,
                  (
                    (FStar_Pervasives_Native_option__bool){
                      .tag = FStar_Pervasives_Native_Some,
                      .v = true
                    }
                  ))
                && n4 > (size_t)0U;
            }
            FStar_Pervasives_Native_option__bool res = pres20;
            if (FStar_Pervasives_Native_uu___is_None__bool(res))
              pres1 = res;
            else
            {
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut0 =
                Pulse_Lib_Slice_split__uint8_t(lt1,
                  CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(lt1, (size_t)0U));
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
              Pulse_Lib_Slice_slice__uint8_t lv1 = scrut4.fst;
              Pulse_Lib_Slice_slice__uint8_t lt_1 = scrut4.snd;
              bool ite0;
              if (res.tag == FStar_Pervasives_Native_Some)
                ite0 = res.v;
              else
                ite0 = KRML_EABORT(bool, "unreachable (pattern matches are exhaustive in F*)");
              if (ite0)
              {
                size_t pn2 = (size_t)1U;
                Pulse_Lib_Slice_slice__uint8_t pl1 = lv;
                Pulse_Lib_Slice_slice__uint8_t pl2 = lv1;
                FStar_Pervasives_Native_option__bool
                pres2 = { .tag = FStar_Pervasives_Native_Some, .v = true };
                size_t n40 = pn2;
                bool
                cond =
                  __eq__FStar_Pervasives_Native_option__bool(pres2,
                    (
                      (FStar_Pervasives_Native_option__bool){
                        .tag = FStar_Pervasives_Native_Some,
                        .v = true
                      }
                    ))
                  && n40 > (size_t)0U;
                while (cond)
                {
                  Pulse_Lib_Slice_slice__uint8_t l1_ = pl1;
                  Pulse_Lib_Slice_slice__uint8_t l2_ = pl2;
                  FStar_Pervasives_Native_option__bool
                  r =
                    CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_map_hd_basic(map_bound_,
                      l1_,
                      l2_);
                  if (FStar_Pervasives_Native_uu___is_None__bool(r))
                    pres2 = r;
                  else
                  {
                    size_t n4 = pn2;
                    if
                    (
                      __eq__FStar_Pervasives_Native_option__bool(r,
                        (
                          (FStar_Pervasives_Native_option__bool){
                            .tag = FStar_Pervasives_Native_Some,
                            .v = true
                          }
                        ))
                    )
                    {
                      size_t n_2 = n4 - (size_t)1U;
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut0 =
                        Pulse_Lib_Slice_split__uint8_t(l1_,
                          CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l1_, (size_t)0U));
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                      Pulse_Lib_Slice_slice__uint8_t
                      tl1 =
                        (
                          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                            .fst = scrut2.fst,
                            .snd = scrut2.snd
                          }
                        ).snd;
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut =
                        Pulse_Lib_Slice_split__uint8_t(l2_,
                          CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l2_, (size_t)0U));
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut3 = { .fst = scrut.fst, .snd = scrut.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                      Pulse_Lib_Slice_slice__uint8_t
                      tl2 =
                        (
                          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                            .fst = scrut4.fst,
                            .snd = scrut4.snd
                          }
                        ).snd;
                      pn2 = n_2;
                      pl1 = tl1;
                      pl2 = tl2;
                    }
                    else
                    {
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut0 =
                        Pulse_Lib_Slice_split__uint8_t(l1_,
                          CBOR_Pulse_Raw_EverParse_Format_jump_header(l1_, (size_t)0U));
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                      Pulse_Lib_Slice_slice__uint8_t tl1 = scrut4.snd;
                      CBOR_Spec_Raw_EverParse_header
                      h11 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut4.fst);
                      uint8_t mt11 = CBOR_Spec_Raw_EverParse_get_header_major_type(h11);
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut5 =
                        Pulse_Lib_Slice_split__uint8_t(l2_,
                          CBOR_Pulse_Raw_EverParse_Format_jump_header(l2_, (size_t)0U));
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
                      Pulse_Lib_Slice_slice__uint8_t tl2 = scrut9.snd;
                      CBOR_Spec_Raw_EverParse_header
                      h21 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut9.fst);
                      if (mt11 != CBOR_Spec_Raw_EverParse_get_header_major_type(h21))
                        pres2 =
                          (
                            (FStar_Pervasives_Native_option__bool){
                              .tag = FStar_Pervasives_Native_Some,
                              .v = false
                            }
                          );
                      else
                      {
                        CBOR_Spec_Raw_EverParse_initial_byte_t b0 = h11.fst;
                        size_t ite0;
                        if
                        (
                          b0.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                            b0.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
                        )
                          ite0 =
                            (size_t)0U +
                              (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h11.fst, h11.snd);
                        else
                          ite0 = (size_t)0U;
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut0 = Pulse_Lib_Slice_split__uint8_t(tl1, ite0);
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                        Pulse_Lib_Slice_slice__uint8_t lc1 = scrut4.fst;
                        Pulse_Lib_Slice_slice__uint8_t tl1_ = scrut4.snd;
                        size_t
                        n_2 =
                          CBOR_Pulse_Raw_EverParse_Format_impl_remaining_data_items_header(h11) +
                            n4 - (size_t)1U;
                        CBOR_Spec_Raw_EverParse_initial_byte_t b = h21.fst;
                        size_t ite1;
                        if
                        (
                          b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                            b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
                        )
                          ite1 =
                            (size_t)0U +
                              (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h21.fst, h21.snd);
                        else
                          ite1 = (size_t)0U;
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut5 = Pulse_Lib_Slice_split__uint8_t(tl2, ite1);
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
                        Pulse_Lib_Slice_slice__uint8_t lc2 = scrut9.fst;
                        Pulse_Lib_Slice_slice__uint8_t tl2_ = scrut9.snd;
                        uint8_t mt12 = CBOR_Spec_Raw_EverParse_get_header_major_type(h11);
                        bool ite2;
                        if (mt12 == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
                        {
                          CBOR_Spec_Raw_EverParse_long_argument
                          scrut0 =
                            FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11);
                          uint8_t ite0;
                          if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                            ite0 =
                              FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11).additional_info;
                          else if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                            ite0 = scrut0.case_LongArgumentSimpleValue;
                          else
                            ite0 =
                              KRML_EABORT(uint8_t,
                                "unreachable (pattern matches are exhaustive in F*)");
                          CBOR_Spec_Raw_EverParse_long_argument
                          scrut =
                            FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21);
                          uint8_t ite;
                          if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                            ite =
                              FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21).additional_info;
                          else if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                            ite = scrut.case_LongArgumentSimpleValue;
                          else
                            ite =
                              KRML_EABORT(uint8_t,
                                "unreachable (pattern matches are exhaustive in F*)");
                          ite2 = ite0 == ite;
                        }
                        else
                        {
                          uint64_t
                          len =
                            CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11),
                              FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11));
                          if
                          (
                            len !=
                              CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21),
                                FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21))
                          )
                            ite2 = false;
                          else if
                          (
                            mt12 == CBOR_MAJOR_TYPE_BYTE_STRING ||
                              mt12 == CBOR_MAJOR_TYPE_TEXT_STRING
                          )
                            ite2 =
                              CBOR_Pulse_Raw_Compare_Bytes_lex_compare_bytes(lc1, lc2) == (int16_t)0;
                          else
                            ite2 = mt12 != CBOR_MAJOR_TYPE_MAP;
                        }
                        if (ite2)
                        {
                          pn2 = n_2;
                          pl1 = tl1_;
                          pl2 = tl2_;
                        }
                        else
                          pres2 =
                            (
                              (FStar_Pervasives_Native_option__bool){
                                .tag = FStar_Pervasives_Native_Some,
                                .v = false
                              }
                            );
                      }
                    }
                  }
                  size_t n4 = pn2;
                  cond =
                    __eq__FStar_Pervasives_Native_option__bool(pres2,
                      (
                        (FStar_Pervasives_Native_option__bool){
                          .tag = FStar_Pervasives_Native_Some,
                          .v = true
                        }
                      ))
                    && n4 > (size_t)0U;
                }
                pres1 = pres2;
                pcont = false;
              }
              else
              {
                pll = lt_1;
                pn1 = n_1;
              }
            }
            size_t n3 = pn1;
            bool cont = pcont;
            cond0 =
              n3 > (size_t)0U &&
                __eq__FStar_Pervasives_Native_option__bool(pres1,
                  (
                    (FStar_Pervasives_Native_option__bool){
                      .tag = FStar_Pervasives_Native_Some,
                      .v = false
                    }
                  ))
              && cont;
          }
          FStar_Pervasives_Native_option__bool res = pres1;
          if
          (
            __eq__FStar_Pervasives_Native_option__bool(res,
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = true
                }
              ))
          )
          {
            pl = lt_;
            pn0 = n_;
          }
          else
            pres0 = res;
          size_t n = pn0;
          cond =
            n > (size_t)0U &&
              __eq__FStar_Pervasives_Native_option__bool(pres0,
                (
                  (FStar_Pervasives_Native_option__bool){
                    .tag = FStar_Pervasives_Native_Some,
                    .v = true
                  }
                ));
        }
        FStar_Pervasives_Native_option__bool res = pres0;
        if
        (
          __eq__FStar_Pervasives_Native_option__bool(res,
            (
              (FStar_Pervasives_Native_option__bool){
                .tag = FStar_Pervasives_Native_Some,
                .v = true
              }
            ))
        )
        {
          Pulse_Lib_Slice_slice__uint8_t pl = c2;
          size_t pn = nv2;
          FStar_Pervasives_Native_option__bool
          pres = { .tag = FStar_Pervasives_Native_Some, .v = true };
          size_t n = pn;
          bool
          cond =
            n > (size_t)0U &&
              __eq__FStar_Pervasives_Native_option__bool(pres,
                (
                  (FStar_Pervasives_Native_option__bool){
                    .tag = FStar_Pervasives_Native_Some,
                    .v = true
                  }
                ));
          while (cond)
          {
            Pulse_Lib_Slice_slice__uint8_t l = pl;
            size_t n_ = pn - (size_t)1U;
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut0 =
              Pulse_Lib_Slice_split__uint8_t(l,
                CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l, (size_t)0U));
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
            Pulse_Lib_Slice_slice__uint8_t lh = scrut4.fst;
            Pulse_Lib_Slice_slice__uint8_t lt = scrut4.snd;
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut5 =
              Pulse_Lib_Slice_split__uint8_t(lt,
                CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(lt, (size_t)0U));
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
            Pulse_Lib_Slice_slice__uint8_t lv = scrut9.fst;
            Pulse_Lib_Slice_slice__uint8_t lt_ = scrut9.snd;
            Pulse_Lib_Slice_slice__uint8_t pll = c1;
            size_t pn1 = nv1;
            FStar_Pervasives_Native_option__bool
            pres1 = { .tag = FStar_Pervasives_Native_Some, .v = false };
            bool pcont = true;
            size_t n3 = pn1;
            bool cont0 = pcont;
            bool
            cond0 =
              n3 > (size_t)0U &&
                __eq__FStar_Pervasives_Native_option__bool(pres1,
                  (
                    (FStar_Pervasives_Native_option__bool){
                      .tag = FStar_Pervasives_Native_Some,
                      .v = false
                    }
                  ))
              && cont0;
            while (cond0)
            {
              Pulse_Lib_Slice_slice__uint8_t l3 = pll;
              size_t n_1 = pn1 - (size_t)1U;
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut0 =
                Pulse_Lib_Slice_split__uint8_t(l3,
                  CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l3, (size_t)0U));
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
              K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
              scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
              Pulse_Lib_Slice_slice__uint8_t lt1 = scrut4.snd;
              size_t pn2 = (size_t)1U;
              Pulse_Lib_Slice_slice__uint8_t pl10 = lh;
              Pulse_Lib_Slice_slice__uint8_t pl20 = scrut4.fst;
              FStar_Pervasives_Native_option__bool
              pres20 = { .tag = FStar_Pervasives_Native_Some, .v = true };
              size_t n40 = pn2;
              bool
              cond =
                __eq__FStar_Pervasives_Native_option__bool(pres20,
                  (
                    (FStar_Pervasives_Native_option__bool){
                      .tag = FStar_Pervasives_Native_Some,
                      .v = true
                    }
                  ))
                && n40 > (size_t)0U;
              while (cond)
              {
                Pulse_Lib_Slice_slice__uint8_t l1_ = pl10;
                Pulse_Lib_Slice_slice__uint8_t l2_ = pl20;
                FStar_Pervasives_Native_option__bool
                r =
                  CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_map_hd_basic(map_bound_,
                    l1_,
                    l2_);
                if (FStar_Pervasives_Native_uu___is_None__bool(r))
                  pres20 = r;
                else
                {
                  size_t n4 = pn2;
                  if
                  (
                    __eq__FStar_Pervasives_Native_option__bool(r,
                      (
                        (FStar_Pervasives_Native_option__bool){
                          .tag = FStar_Pervasives_Native_Some,
                          .v = true
                        }
                      ))
                  )
                  {
                    size_t n_2 = n4 - (size_t)1U;
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut0 =
                      Pulse_Lib_Slice_split__uint8_t(l1_,
                        CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l1_, (size_t)0U));
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                    Pulse_Lib_Slice_slice__uint8_t
                    tl1 =
                      (
                        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                          .fst = scrut2.fst,
                          .snd = scrut2.snd
                        }
                      ).snd;
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut =
                      Pulse_Lib_Slice_split__uint8_t(l2_,
                        CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l2_, (size_t)0U));
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut3 = { .fst = scrut.fst, .snd = scrut.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                    Pulse_Lib_Slice_slice__uint8_t
                    tl2 =
                      (
                        (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                          .fst = scrut4.fst,
                          .snd = scrut4.snd
                        }
                      ).snd;
                    pn2 = n_2;
                    pl10 = tl1;
                    pl20 = tl2;
                  }
                  else
                  {
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut0 =
                      Pulse_Lib_Slice_split__uint8_t(l1_,
                        CBOR_Pulse_Raw_EverParse_Format_jump_header(l1_, (size_t)0U));
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                    Pulse_Lib_Slice_slice__uint8_t tl1 = scrut4.snd;
                    CBOR_Spec_Raw_EverParse_header
                    h11 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut4.fst);
                    uint8_t mt11 = CBOR_Spec_Raw_EverParse_get_header_major_type(h11);
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut5 =
                      Pulse_Lib_Slice_split__uint8_t(l2_,
                        CBOR_Pulse_Raw_EverParse_Format_jump_header(l2_, (size_t)0U));
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
                    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                    scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
                    Pulse_Lib_Slice_slice__uint8_t tl2 = scrut9.snd;
                    CBOR_Spec_Raw_EverParse_header
                    h21 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut9.fst);
                    if (mt11 != CBOR_Spec_Raw_EverParse_get_header_major_type(h21))
                      pres20 =
                        (
                          (FStar_Pervasives_Native_option__bool){
                            .tag = FStar_Pervasives_Native_Some,
                            .v = false
                          }
                        );
                    else
                    {
                      CBOR_Spec_Raw_EverParse_initial_byte_t b0 = h11.fst;
                      size_t ite0;
                      if
                      (
                        b0.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                          b0.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
                      )
                        ite0 =
                          (size_t)0U +
                            (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h11.fst, h11.snd);
                      else
                        ite0 = (size_t)0U;
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut0 = Pulse_Lib_Slice_split__uint8_t(tl1, ite0);
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                      Pulse_Lib_Slice_slice__uint8_t lc1 = scrut4.fst;
                      Pulse_Lib_Slice_slice__uint8_t tl1_ = scrut4.snd;
                      size_t
                      n_2 =
                        CBOR_Pulse_Raw_EverParse_Format_impl_remaining_data_items_header(h11) +
                          n4 - (size_t)1U;
                      CBOR_Spec_Raw_EverParse_initial_byte_t b = h21.fst;
                      size_t ite1;
                      if
                      (
                        b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                          b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
                      )
                        ite1 =
                          (size_t)0U +
                            (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h21.fst, h21.snd);
                      else
                        ite1 = (size_t)0U;
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut5 = Pulse_Lib_Slice_split__uint8_t(tl2, ite1);
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
                      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                      scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
                      Pulse_Lib_Slice_slice__uint8_t lc2 = scrut9.fst;
                      Pulse_Lib_Slice_slice__uint8_t tl2_ = scrut9.snd;
                      uint8_t mt12 = CBOR_Spec_Raw_EverParse_get_header_major_type(h11);
                      bool ite2;
                      if (mt12 == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
                      {
                        CBOR_Spec_Raw_EverParse_long_argument
                        scrut0 =
                          FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11);
                        uint8_t ite0;
                        if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                          ite0 =
                            FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11).additional_info;
                        else if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                          ite0 = scrut0.case_LongArgumentSimpleValue;
                        else
                          ite0 =
                            KRML_EABORT(uint8_t,
                              "unreachable (pattern matches are exhaustive in F*)");
                        CBOR_Spec_Raw_EverParse_long_argument
                        scrut =
                          FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21);
                        uint8_t ite;
                        if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                          ite =
                            FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21).additional_info;
                        else if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                          ite = scrut.case_LongArgumentSimpleValue;
                        else
                          ite =
                            KRML_EABORT(uint8_t,
                              "unreachable (pattern matches are exhaustive in F*)");
                        ite2 = ite0 == ite;
                      }
                      else
                      {
                        uint64_t
                        len =
                          CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11),
                            FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11));
                        if
                        (
                          len !=
                            CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21),
                              FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21))
                        )
                          ite2 = false;
                        else if
                        (mt12 == CBOR_MAJOR_TYPE_BYTE_STRING || mt12 == CBOR_MAJOR_TYPE_TEXT_STRING)
                          ite2 =
                            CBOR_Pulse_Raw_Compare_Bytes_lex_compare_bytes(lc1, lc2) == (int16_t)0;
                        else
                          ite2 = mt12 != CBOR_MAJOR_TYPE_MAP;
                      }
                      if (ite2)
                      {
                        pn2 = n_2;
                        pl10 = tl1_;
                        pl20 = tl2_;
                      }
                      else
                        pres20 =
                          (
                            (FStar_Pervasives_Native_option__bool){
                              .tag = FStar_Pervasives_Native_Some,
                              .v = false
                            }
                          );
                    }
                  }
                }
                size_t n4 = pn2;
                cond =
                  __eq__FStar_Pervasives_Native_option__bool(pres20,
                    (
                      (FStar_Pervasives_Native_option__bool){
                        .tag = FStar_Pervasives_Native_Some,
                        .v = true
                      }
                    ))
                  && n4 > (size_t)0U;
              }
              FStar_Pervasives_Native_option__bool res1 = pres20;
              if (FStar_Pervasives_Native_uu___is_None__bool(res1))
                pres1 = res1;
              else
              {
                K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                scrut0 =
                  Pulse_Lib_Slice_split__uint8_t(lt1,
                    CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(lt1, (size_t)0U));
                K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                Pulse_Lib_Slice_slice__uint8_t lv1 = scrut4.fst;
                Pulse_Lib_Slice_slice__uint8_t lt_1 = scrut4.snd;
                bool ite0;
                if (res1.tag == FStar_Pervasives_Native_Some)
                  ite0 = res1.v;
                else
                  ite0 = KRML_EABORT(bool, "unreachable (pattern matches are exhaustive in F*)");
                if (ite0)
                {
                  size_t pn2 = (size_t)1U;
                  Pulse_Lib_Slice_slice__uint8_t pl1 = lv;
                  Pulse_Lib_Slice_slice__uint8_t pl2 = lv1;
                  FStar_Pervasives_Native_option__bool
                  pres2 = { .tag = FStar_Pervasives_Native_Some, .v = true };
                  size_t n40 = pn2;
                  bool
                  cond =
                    __eq__FStar_Pervasives_Native_option__bool(pres2,
                      (
                        (FStar_Pervasives_Native_option__bool){
                          .tag = FStar_Pervasives_Native_Some,
                          .v = true
                        }
                      ))
                    && n40 > (size_t)0U;
                  while (cond)
                  {
                    Pulse_Lib_Slice_slice__uint8_t l1_ = pl1;
                    Pulse_Lib_Slice_slice__uint8_t l2_ = pl2;
                    FStar_Pervasives_Native_option__bool
                    r =
                      CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_map_hd_basic(map_bound_,
                        l1_,
                        l2_);
                    if (FStar_Pervasives_Native_uu___is_None__bool(r))
                      pres2 = r;
                    else
                    {
                      size_t n4 = pn2;
                      if
                      (
                        __eq__FStar_Pervasives_Native_option__bool(r,
                          (
                            (FStar_Pervasives_Native_option__bool){
                              .tag = FStar_Pervasives_Native_Some,
                              .v = true
                            }
                          ))
                      )
                      {
                        size_t n_2 = n4 - (size_t)1U;
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut0 =
                          Pulse_Lib_Slice_split__uint8_t(l1_,
                            CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l1_, (size_t)0U));
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                        Pulse_Lib_Slice_slice__uint8_t
                        tl1 =
                          (
                            (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                              .fst = scrut2.fst,
                              .snd = scrut2.snd
                            }
                          ).snd;
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut =
                          Pulse_Lib_Slice_split__uint8_t(l2_,
                            CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l2_, (size_t)0U));
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut3 = { .fst = scrut.fst, .snd = scrut.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                        Pulse_Lib_Slice_slice__uint8_t
                        tl2 =
                          (
                            (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                              .fst = scrut4.fst,
                              .snd = scrut4.snd
                            }
                          ).snd;
                        pn2 = n_2;
                        pl1 = tl1;
                        pl2 = tl2;
                      }
                      else
                      {
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut0 =
                          Pulse_Lib_Slice_split__uint8_t(l1_,
                            CBOR_Pulse_Raw_EverParse_Format_jump_header(l1_, (size_t)0U));
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                        Pulse_Lib_Slice_slice__uint8_t tl1 = scrut4.snd;
                        CBOR_Spec_Raw_EverParse_header
                        h11 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut4.fst);
                        uint8_t mt11 = CBOR_Spec_Raw_EverParse_get_header_major_type(h11);
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut5 =
                          Pulse_Lib_Slice_split__uint8_t(l2_,
                            CBOR_Pulse_Raw_EverParse_Format_jump_header(l2_, (size_t)0U));
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
                        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                        scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
                        Pulse_Lib_Slice_slice__uint8_t tl2 = scrut9.snd;
                        CBOR_Spec_Raw_EverParse_header
                        h21 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut9.fst);
                        if (mt11 != CBOR_Spec_Raw_EverParse_get_header_major_type(h21))
                          pres2 =
                            (
                              (FStar_Pervasives_Native_option__bool){
                                .tag = FStar_Pervasives_Native_Some,
                                .v = false
                              }
                            );
                        else
                        {
                          CBOR_Spec_Raw_EverParse_initial_byte_t b0 = h11.fst;
                          size_t ite0;
                          if
                          (
                            b0.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                              b0.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
                          )
                            ite0 =
                              (size_t)0U +
                                (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h11.fst, h11.snd);
                          else
                            ite0 = (size_t)0U;
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut0 = Pulse_Lib_Slice_split__uint8_t(tl1, ite0);
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
                          Pulse_Lib_Slice_slice__uint8_t lc1 = scrut4.fst;
                          Pulse_Lib_Slice_slice__uint8_t tl1_ = scrut4.snd;
                          size_t
                          n_2 =
                            CBOR_Pulse_Raw_EverParse_Format_impl_remaining_data_items_header(h11) +
                              n4 - (size_t)1U;
                          CBOR_Spec_Raw_EverParse_initial_byte_t b = h21.fst;
                          size_t ite1;
                          if
                          (
                            b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                              b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
                          )
                            ite1 =
                              (size_t)0U +
                                (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h21.fst, h21.snd);
                          else
                            ite1 = (size_t)0U;
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut5 = Pulse_Lib_Slice_split__uint8_t(tl2, ite1);
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
                          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
                          scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
                          Pulse_Lib_Slice_slice__uint8_t lc2 = scrut9.fst;
                          Pulse_Lib_Slice_slice__uint8_t tl2_ = scrut9.snd;
                          uint8_t mt12 = CBOR_Spec_Raw_EverParse_get_header_major_type(h11);
                          bool ite2;
                          if (mt12 == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
                          {
                            CBOR_Spec_Raw_EverParse_long_argument
                            scrut0 =
                              FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11);
                            uint8_t ite0;
                            if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                              ite0 =
                                FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11).additional_info;
                            else if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                              ite0 = scrut0.case_LongArgumentSimpleValue;
                            else
                              ite0 =
                                KRML_EABORT(uint8_t,
                                  "unreachable (pattern matches are exhaustive in F*)");
                            CBOR_Spec_Raw_EverParse_long_argument
                            scrut =
                              FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21);
                            uint8_t ite;
                            if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                              ite =
                                FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21).additional_info;
                            else if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                              ite = scrut.case_LongArgumentSimpleValue;
                            else
                              ite =
                                KRML_EABORT(uint8_t,
                                  "unreachable (pattern matches are exhaustive in F*)");
                            ite2 = ite0 == ite;
                          }
                          else
                          {
                            uint64_t
                            len =
                              CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11),
                                FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h11));
                            if
                            (
                              len !=
                                CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21),
                                  FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h21))
                            )
                              ite2 = false;
                            else if
                            (
                              mt12 == CBOR_MAJOR_TYPE_BYTE_STRING ||
                                mt12 == CBOR_MAJOR_TYPE_TEXT_STRING
                            )
                              ite2 =
                                CBOR_Pulse_Raw_Compare_Bytes_lex_compare_bytes(lc1, lc2) ==
                                  (int16_t)0;
                            else
                              ite2 = mt12 != CBOR_MAJOR_TYPE_MAP;
                          }
                          if (ite2)
                          {
                            pn2 = n_2;
                            pl1 = tl1_;
                            pl2 = tl2_;
                          }
                          else
                            pres2 =
                              (
                                (FStar_Pervasives_Native_option__bool){
                                  .tag = FStar_Pervasives_Native_Some,
                                  .v = false
                                }
                              );
                        }
                      }
                    }
                    size_t n4 = pn2;
                    cond =
                      __eq__FStar_Pervasives_Native_option__bool(pres2,
                        (
                          (FStar_Pervasives_Native_option__bool){
                            .tag = FStar_Pervasives_Native_Some,
                            .v = true
                          }
                        ))
                      && n4 > (size_t)0U;
                  }
                  pres1 = pres2;
                  pcont = false;
                }
                else
                {
                  pll = lt_1;
                  pn1 = n_1;
                }
              }
              size_t n3 = pn1;
              bool cont = pcont;
              cond0 =
                n3 > (size_t)0U &&
                  __eq__FStar_Pervasives_Native_option__bool(pres1,
                    (
                      (FStar_Pervasives_Native_option__bool){
                        .tag = FStar_Pervasives_Native_Some,
                        .v = false
                      }
                    ))
                && cont;
            }
            FStar_Pervasives_Native_option__bool res1 = pres1;
            if
            (
              __eq__FStar_Pervasives_Native_option__bool(res1,
                (
                  (FStar_Pervasives_Native_option__bool){
                    .tag = FStar_Pervasives_Native_Some,
                    .v = true
                  }
                ))
            )
            {
              pl = lt_;
              pn = n_;
            }
            else
              pres = res1;
            size_t n = pn;
            cond =
              n > (size_t)0U &&
                __eq__FStar_Pervasives_Native_option__bool(pres,
                  (
                    (FStar_Pervasives_Native_option__bool){
                      .tag = FStar_Pervasives_Native_Some,
                      .v = true
                    }
                  ));
          }
          return pres;
        }
        else
          return res;
      }
    else
      return
        ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = false });
  }
}

static FStar_Pervasives_Native_option__bool
CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_list_basic(
  FStar_Pervasives_Native_option__size_t map_bound,
  size_t n1,
  Pulse_Lib_Slice_slice__uint8_t l1,
  size_t n2,
  Pulse_Lib_Slice_slice__uint8_t l2
)
{
  if (n1 != n2)
    return
      ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = false });
  else
  {
    size_t pn = n1;
    Pulse_Lib_Slice_slice__uint8_t pl1 = l1;
    Pulse_Lib_Slice_slice__uint8_t pl2 = l2;
    FStar_Pervasives_Native_option__bool pres = { .tag = FStar_Pervasives_Native_Some, .v = true };
    size_t n0 = pn;
    bool
    cond =
      __eq__FStar_Pervasives_Native_option__bool(pres,
        ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }))
      && n0 > (size_t)0U;
    while (cond)
    {
      Pulse_Lib_Slice_slice__uint8_t l1_ = pl1;
      Pulse_Lib_Slice_slice__uint8_t l2_ = pl2;
      FStar_Pervasives_Native_option__bool
      r = CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_map_hd_basic(map_bound, l1_, l2_);
      if (FStar_Pervasives_Native_uu___is_None__bool(r))
        pres = r;
      else
      {
        size_t n = pn;
        if
        (
          __eq__FStar_Pervasives_Native_option__bool(r,
            (
              (FStar_Pervasives_Native_option__bool){
                .tag = FStar_Pervasives_Native_Some,
                .v = true
              }
            ))
        )
        {
          size_t n_ = n - (size_t)1U;
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut0 =
            Pulse_Lib_Slice_split__uint8_t(l1_,
              CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l1_, (size_t)0U));
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
          Pulse_Lib_Slice_slice__uint8_t
          tl1 =
            (
              (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                .fst = scrut2.fst,
                .snd = scrut2.snd
              }
            ).snd;
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut =
            Pulse_Lib_Slice_split__uint8_t(l2_,
              CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l2_, (size_t)0U));
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut3 = { .fst = scrut.fst, .snd = scrut.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
          Pulse_Lib_Slice_slice__uint8_t
          tl2 =
            (
              (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                .fst = scrut4.fst,
                .snd = scrut4.snd
              }
            ).snd;
          pn = n_;
          pl1 = tl1;
          pl2 = tl2;
        }
        else
        {
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut0 =
            Pulse_Lib_Slice_split__uint8_t(l1_,
              CBOR_Pulse_Raw_EverParse_Format_jump_header(l1_, (size_t)0U));
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
          Pulse_Lib_Slice_slice__uint8_t tl1 = scrut4.snd;
          CBOR_Spec_Raw_EverParse_header
          h1 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut4.fst);
          uint8_t mt1 = CBOR_Spec_Raw_EverParse_get_header_major_type(h1);
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut5 =
            Pulse_Lib_Slice_split__uint8_t(l2_,
              CBOR_Pulse_Raw_EverParse_Format_jump_header(l2_, (size_t)0U));
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
          Pulse_Lib_Slice_slice__uint8_t tl2 = scrut9.snd;
          CBOR_Spec_Raw_EverParse_header
          h2 = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut9.fst);
          if (mt1 != CBOR_Spec_Raw_EverParse_get_header_major_type(h2))
            pres =
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = false
                }
              );
          else
          {
            CBOR_Spec_Raw_EverParse_initial_byte_t b0 = h1.fst;
            size_t ite0;
            if
            (
              b0.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                b0.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
            )
              ite0 = (size_t)0U + (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h1.fst, h1.snd);
            else
              ite0 = (size_t)0U;
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut0 = Pulse_Lib_Slice_split__uint8_t(tl1, ite0);
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
            Pulse_Lib_Slice_slice__uint8_t lc1 = scrut4.fst;
            Pulse_Lib_Slice_slice__uint8_t tl1_ = scrut4.snd;
            size_t
            n_ =
              CBOR_Pulse_Raw_EverParse_Format_impl_remaining_data_items_header(h1) + n - (size_t)1U;
            CBOR_Spec_Raw_EverParse_initial_byte_t b = h2.fst;
            size_t ite1;
            if
            (
              b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING ||
                b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING
            )
              ite1 = (size_t)0U + (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(h2.fst, h2.snd);
            else
              ite1 = (size_t)0U;
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut5 = Pulse_Lib_Slice_split__uint8_t(tl2, ite1);
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
            Pulse_Lib_Slice_slice__uint8_t lc2 = scrut9.fst;
            Pulse_Lib_Slice_slice__uint8_t tl2_ = scrut9.snd;
            uint8_t mt11 = CBOR_Spec_Raw_EverParse_get_header_major_type(h1);
            bool ite2;
            if (mt11 == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
            {
              CBOR_Spec_Raw_EverParse_long_argument
              scrut0 =
                FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h1);
              uint8_t ite0;
              if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                ite0 =
                  FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h1).additional_info;
              else if (scrut0.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                ite0 = scrut0.case_LongArgumentSimpleValue;
              else
                ite0 = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
              CBOR_Spec_Raw_EverParse_long_argument
              scrut =
                FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h2);
              uint8_t ite;
              if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentOther)
                ite =
                  FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h2).additional_info;
              else if (scrut.tag == CBOR_Spec_Raw_EverParse_LongArgumentSimpleValue)
                ite = scrut.case_LongArgumentSimpleValue;
              else
                ite = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
              ite2 = ite0 == ite;
            }
            else
            {
              uint64_t
              len =
                CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h1),
                  FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h1));
              if
              (
                len !=
                  CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h2),
                    FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h2))
              )
                ite2 = false;
              else if (mt11 == CBOR_MAJOR_TYPE_BYTE_STRING || mt11 == CBOR_MAJOR_TYPE_TEXT_STRING)
                ite2 = CBOR_Pulse_Raw_Compare_Bytes_lex_compare_bytes(lc1, lc2) == (int16_t)0;
              else
                ite2 = mt11 != CBOR_MAJOR_TYPE_MAP;
            }
            if (ite2)
            {
              pn = n_;
              pl1 = tl1_;
              pl2 = tl2_;
            }
            else
              pres =
                (
                  (FStar_Pervasives_Native_option__bool){
                    .tag = FStar_Pervasives_Native_Some,
                    .v = false
                  }
                );
          }
        }
      }
      size_t n = pn;
      cond =
        __eq__FStar_Pervasives_Native_option__bool(pres,
          ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }))
        && n > (size_t)0U;
    }
    return pres;
  }
}

static FStar_Pervasives_Native_option__bool
CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_basic(
  FStar_Pervasives_Native_option__size_t map_bound,
  Pulse_Lib_Slice_slice__uint8_t l1,
  Pulse_Lib_Slice_slice__uint8_t l2
)
{
  return
    CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_list_basic(map_bound,
      (size_t)1U,
      l1,
      (size_t)1U,
      l2);
}

static FStar_Pervasives_Native_option__bool
CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_list_for_all_with_overflow_setoid_assoc_eq_with_overflow_basic(
  size_t nl1,
  Pulse_Lib_Slice_slice__uint8_t l1,
  size_t nl2,
  Pulse_Lib_Slice_slice__uint8_t l2
)
{
  Pulse_Lib_Slice_slice__uint8_t pl = l2;
  size_t pn = nl2;
  FStar_Pervasives_Native_option__bool pres = { .tag = FStar_Pervasives_Native_Some, .v = true };
  size_t n = pn;
  bool
  cond =
    n > (size_t)0U &&
      __eq__FStar_Pervasives_Native_option__bool(pres,
        ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }));
  while (cond)
  {
    Pulse_Lib_Slice_slice__uint8_t l = pl;
    size_t n_ = pn - (size_t)1U;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 =
      Pulse_Lib_Slice_split__uint8_t(l,
        CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l, (size_t)0U));
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
    Pulse_Lib_Slice_slice__uint8_t lh = scrut4.fst;
    Pulse_Lib_Slice_slice__uint8_t lt = scrut4.snd;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut5 =
      Pulse_Lib_Slice_split__uint8_t(lt,
        CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(lt, (size_t)0U));
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut8 = { .fst = scrut7.fst, .snd = scrut7.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut9 = { .fst = scrut8.fst, .snd = scrut8.snd };
    Pulse_Lib_Slice_slice__uint8_t lv = scrut9.fst;
    Pulse_Lib_Slice_slice__uint8_t lt_ = scrut9.snd;
    Pulse_Lib_Slice_slice__uint8_t pll = l1;
    size_t pn1 = nl1;
    FStar_Pervasives_Native_option__bool
    pres1 = { .tag = FStar_Pervasives_Native_Some, .v = false };
    bool pcont = true;
    size_t n1 = pn1;
    bool cont0 = pcont;
    bool
    cond0 =
      n1 > (size_t)0U &&
        __eq__FStar_Pervasives_Native_option__bool(pres1,
          (
            (FStar_Pervasives_Native_option__bool){
              .tag = FStar_Pervasives_Native_Some,
              .v = false
            }
          ))
      && cont0;
    while (cond0)
    {
      Pulse_Lib_Slice_slice__uint8_t l3 = pll;
      size_t n_1 = pn1 - (size_t)1U;
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut0 =
        Pulse_Lib_Slice_split__uint8_t(l3,
          CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l3, (size_t)0U));
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
      Pulse_Lib_Slice_slice__uint8_t lt1 = scrut4.snd;
      FStar_Pervasives_Native_option__bool
      res =
        CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_basic((
            (FStar_Pervasives_Native_option__size_t){ .tag = FStar_Pervasives_Native_None }
          ),
          lh,
          scrut4.fst);
      if (FStar_Pervasives_Native_uu___is_None__bool(res))
        pres1 = res;
      else
      {
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut =
          Pulse_Lib_Slice_split__uint8_t(lt1,
            CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(lt1, (size_t)0U));
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
        Pulse_Lib_Slice_slice__uint8_t lv1 = scrut3.fst;
        Pulse_Lib_Slice_slice__uint8_t lt_1 = scrut3.snd;
        bool ite;
        if (res.tag == FStar_Pervasives_Native_Some)
          ite = res.v;
        else
          ite = KRML_EABORT(bool, "unreachable (pattern matches are exhaustive in F*)");
        if (ite)
        {
          pres1 =
            CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_basic((
                (FStar_Pervasives_Native_option__size_t){ .tag = FStar_Pervasives_Native_None }
              ),
              lv,
              lv1);
          pcont = false;
        }
        else
        {
          pll = lt_1;
          pn1 = n_1;
        }
      }
      size_t n1 = pn1;
      bool cont = pcont;
      cond0 =
        n1 > (size_t)0U &&
          __eq__FStar_Pervasives_Native_option__bool(pres1,
            (
              (FStar_Pervasives_Native_option__bool){
                .tag = FStar_Pervasives_Native_Some,
                .v = false
              }
            ))
        && cont;
    }
    FStar_Pervasives_Native_option__bool res = pres1;
    if
    (
      __eq__FStar_Pervasives_Native_option__bool(res,
        ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }))
    )
    {
      pl = lt_;
      pn = n_;
    }
    else
      pres = res;
    size_t n = pn;
    cond =
      n > (size_t)0U &&
        __eq__FStar_Pervasives_Native_option__bool(pres,
          ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }));
  }
  return pres;
}

static bool
CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_valid_basic(
  FStar_Pervasives_Native_option__size_t map_bound,
  bool strict_bound_check,
  Pulse_Lib_Slice_slice__uint8_t l1
)
{
  size_t pn = (size_t)1U;
  bool pres = true;
  Pulse_Lib_Slice_slice__uint8_t ppi = l1;
  while (pres && pn > (size_t)0U)
  {
    size_t n = pn;
    Pulse_Lib_Slice_slice__uint8_t pi = ppi;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 =
      Pulse_Lib_Slice_split__uint8_t(pi,
        CBOR_Pulse_Raw_EverParse_Format_jump_header(pi, (size_t)0U));
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
    CBOR_Spec_Raw_EverParse_header
    h =
      CBOR_Pulse_Raw_EverParse_Format_read_header((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut3.fst,
            .snd = scrut3.snd
          }
        ).fst);
    bool ite0;
    if (CBOR_Spec_Raw_EverParse_get_header_major_type(h) == CBOR_MAJOR_TYPE_MAP)
    {
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut0 =
        Pulse_Lib_Slice_split__uint8_t(pi,
          CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(pi, (size_t)0U));
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
      Pulse_Lib_Slice_slice__uint8_t
      hd =
        (
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut2.fst,
            .snd = scrut2.snd
          }
        ).fst;
      CBOR_Spec_Raw_EverParse_header ph = h;
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut =
        Pulse_Lib_Slice_split__uint8_t(hd,
          CBOR_Pulse_Raw_EverParse_Format_jump_header(hd, (size_t)0U));
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut3 = { .fst = scrut.fst, .snd = scrut.snd };
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
      Pulse_Lib_Slice_slice__uint8_t outc = scrut4.snd;
      ph = CBOR_Pulse_Raw_EverParse_Format_read_header(scrut4.fst);
      Pulse_Lib_Slice_slice__uint8_t pl = outc;
      size_t
      pn1 =
        (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(FStar_Pervasives_dfst__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h),
          FStar_Pervasives_dsnd__CBOR_Spec_Raw_EverParse_initial_byte_t_CBOR_Spec_Raw_EverParse_long_argument(h));
      FStar_Pervasives_Native_option__bool
      pres1 = { .tag = FStar_Pervasives_Native_Some, .v = true };
      size_t n1 = pn1;
      bool
      cond =
        n1 > (size_t)0U &&
          __eq__FStar_Pervasives_Native_option__bool(pres1,
            (
              (FStar_Pervasives_Native_option__bool){
                .tag = FStar_Pervasives_Native_Some,
                .v = true
              }
            ));
      while (cond)
      {
        size_t n_ = pn1 - (size_t)1U;
        Pulse_Lib_Slice_slice__uint8_t l = pl;
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut =
          Pulse_Lib_Slice_split__uint8_t(l,
            CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l, (size_t)0U));
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
        Pulse_Lib_Slice_slice__uint8_t lh = scrut3.fst;
        Pulse_Lib_Slice_slice__uint8_t lt = scrut3.snd;
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut4 =
          Pulse_Lib_Slice_split__uint8_t(lt,
            CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(lt, (size_t)0U));
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut5 = { .fst = scrut4.fst, .snd = scrut4.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut6 = { .fst = scrut5.fst, .snd = scrut5.snd };
        K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
        scrut7 = { .fst = scrut6.fst, .snd = scrut6.snd };
        Pulse_Lib_Slice_slice__uint8_t
        lt_ =
          (
            (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
              .fst = scrut7.fst,
              .snd = scrut7.snd
            }
          ).snd;
        Pulse_Lib_Slice_slice__uint8_t pl1 = lt_;
        size_t pn2 = n_;
        FStar_Pervasives_Native_option__bool
        pres2 = { .tag = FStar_Pervasives_Native_Some, .v = false };
        size_t n2 = pn2;
        bool
        cond0 =
          n2 > (size_t)0U &&
            __eq__FStar_Pervasives_Native_option__bool(pres2,
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = false
                }
              ));
        while (cond0)
        {
          size_t n_1 = pn2 - (size_t)1U;
          Pulse_Lib_Slice_slice__uint8_t l2 = pl1;
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut =
            Pulse_Lib_Slice_split__uint8_t(l2,
              CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(l2, (size_t)0U));
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
          K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
          scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
          Pulse_Lib_Slice_slice__uint8_t lt1 = scrut3.snd;
          FStar_Pervasives_Native_option__bool
          res =
            CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_basic(map_bound,
              lh,
              scrut3.fst);
          if
          (
            __eq__FStar_Pervasives_Native_option__bool(res,
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = false
                }
              ))
          )
          {
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut =
              Pulse_Lib_Slice_split__uint8_t(lt1,
                CBOR_Pulse_Raw_EverParse_Format_jump_raw_data_item(lt1, (size_t)0U));
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut0 = { .fst = scrut.fst, .snd = scrut.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
            K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
            scrut2 = { .fst = scrut1.fst, .snd = scrut1.snd };
            pl1 =
              (
                (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
                  .fst = scrut2.fst,
                  .snd = scrut2.snd
                }
              ).snd;
            pn2 = n_1;
          }
          else
            pres2 = res;
          size_t n2 = pn2;
          cond0 =
            n2 > (size_t)0U &&
              __eq__FStar_Pervasives_Native_option__bool(pres2,
                (
                  (FStar_Pervasives_Native_option__bool){
                    .tag = FStar_Pervasives_Native_Some,
                    .v = false
                  }
                ));
        }
        FStar_Pervasives_Native_option__bool res = pres2;
        if (FStar_Pervasives_Native_uu___is_None__bool(res))
          pres1 = ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_None });
        else
        {
          bool ite;
          if (res.tag == FStar_Pervasives_Native_Some)
            ite = res.v;
          else
            ite = KRML_EABORT(bool, "unreachable (pattern matches are exhaustive in F*)");
          if (ite)
            pres1 =
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = false
                }
              );
          else
          {
            FStar_Pervasives_Native_option__size_t ite;
            if (strict_bound_check)
              ite = map_bound;
            else
              ite =
                ((FStar_Pervasives_Native_option__size_t){ .tag = FStar_Pervasives_Native_None });
            if (CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth_opt(ite, (size_t)1U, lh))
            {
              pn1 = n_;
              pl = lt_;
            }
            else
              pres1 =
                ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_None });
          }
        }
        size_t n1 = pn1;
        cond =
          n1 > (size_t)0U &&
            __eq__FStar_Pervasives_Native_option__bool(pres1,
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = true
                }
              ));
      }
      ite0 =
        __eq__FStar_Pervasives_Native_option__bool(pres1,
          ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }));
    }
    else
      ite0 = true;
    if (!ite0)
      pres = false;
    else
    {
      size_t off1 = CBOR_Pulse_Raw_EverParse_Format_jump_header(pi, (size_t)0U);
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut = Pulse_Lib_Slice_split__uint8_t(pi, (size_t)0U);
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut0 =
        Pulse_Lib_Slice_split__uint8_t((
            (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
              .fst = scrut.fst,
              .snd = scrut.snd
            }
          ).snd,
          off1 - (size_t)0U);
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
      CBOR_Spec_Raw_EverParse_header
      x =
        CBOR_Pulse_Raw_EverParse_Format_read_header((
            (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
              .fst = scrut1.fst,
              .snd = scrut1.snd
            }
          ).fst);
      CBOR_Spec_Raw_EverParse_initial_byte_t b = x.fst;
      size_t ite;
      if
      (b.major_type == CBOR_MAJOR_TYPE_BYTE_STRING || b.major_type == CBOR_MAJOR_TYPE_TEXT_STRING)
        ite = off1 + (size_t)CBOR_Spec_Raw_EverParse_argument_as_uint64(x.fst, x.snd);
      else
        ite = off1 + (size_t)0U;
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut2 = Pulse_Lib_Slice_split__uint8_t(pi, ite);
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut3 = { .fst = scrut2.fst, .snd = scrut2.snd };
      K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
      scrut4 = { .fst = scrut3.fst, .snd = scrut3.snd };
      Pulse_Lib_Slice_slice__uint8_t ph = scrut4.fst;
      Pulse_Lib_Slice_slice__uint8_t pc = scrut4.snd;
      size_t unused = Pulse_Lib_Slice_len__uint8_t(pc);
      KRML_MAYBE_UNUSED_VAR(unused);
      pn = n - (size_t)1U + CBOR_Pulse_Raw_EverParse_Format_jump_recursive_step_count_leaf(ph);
      ppi = pc;
    }
  }
  return pres;
}

static size_t
CBOR_Pulse_Raw_Format_Nondet_Validate_cbor_validate_nondet(
  FStar_Pervasives_Native_option__size_t map_key_bound,
  bool strict_check,
  Pulse_Lib_Slice_slice__uint8_t input
)
{
  size_t poff = (size_t)0U;
  if (CBOR_Pulse_Raw_EverParse_Format_validate_raw_data_item(input, &poff))
  {
    size_t off = poff;
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut = Pulse_Lib_Slice_split__uint8_t(input, (size_t)0U);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut0 =
      Pulse_Lib_Slice_split__uint8_t((
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut.fst,
            .snd = scrut.snd
          }
        ).snd,
        off - (size_t)0U);
    K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t
    scrut1 = { .fst = scrut0.fst, .snd = scrut0.snd };
    if
    (
      CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_valid_basic(map_key_bound,
        strict_check,
        (
          (K___Pulse_Lib_Slice_slice_uint8_t_Pulse_Lib_Slice_slice_uint8_t){
            .fst = scrut1.fst,
            .snd = scrut1.snd
          }
        ).fst)
    )
      return off;
    else
      return (size_t)0U;
  }
  else
    return (size_t)0U;
}

static bool
CBOR_Pulse_Raw_Format_Nondet_Compare_cbor_match_equal_serialized_tagged(
  cbor_serialized c1,
  cbor_serialized c2
)
{
  if (c1.cbor_serialized_header.value != c2.cbor_serialized_header.value)
    return false;
  else
    return
      __eq__FStar_Pervasives_Native_option__bool(CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_basic((
            (FStar_Pervasives_Native_option__size_t){ .tag = FStar_Pervasives_Native_None }
          ),
          c1.cbor_serialized_payload,
          c2.cbor_serialized_payload),
        ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }));
}

static bool
CBOR_Pulse_Raw_Format_Nondet_Compare_cbor_match_compare_serialized_array(
  cbor_serialized c1,
  cbor_serialized c2
)
{
  return
    __eq__FStar_Pervasives_Native_option__bool(CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_list_basic((
          (FStar_Pervasives_Native_option__size_t){ .tag = FStar_Pervasives_Native_None }
        ),
        (size_t)c1.cbor_serialized_header.value,
        c1.cbor_serialized_payload,
        (size_t)c2.cbor_serialized_header.value,
        c2.cbor_serialized_payload),
      ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }));
}

static bool
CBOR_Pulse_Raw_Format_Nondet_Compare_cbor_match_compare_serialized_map(
  cbor_serialized c1,
  cbor_serialized c2
)
{
  size_t n1 = (size_t)c1.cbor_serialized_header.value;
  size_t n2 = (size_t)c2.cbor_serialized_header.value;
  if
  (
    __eq__FStar_Pervasives_Native_option__bool(CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_list_for_all_with_overflow_setoid_assoc_eq_with_overflow_basic(n2,
        c2.cbor_serialized_payload,
        n1,
        c1.cbor_serialized_payload),
      ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }))
  )
    return
      __eq__FStar_Pervasives_Native_option__bool(CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_list_for_all_with_overflow_setoid_assoc_eq_with_overflow_basic(n1,
          c1.cbor_serialized_payload,
          n2,
          c2.cbor_serialized_payload),
        ((FStar_Pervasives_Native_option__bool){ .tag = FStar_Pervasives_Native_Some, .v = true }));
  else
    return false;
}

static bool
FStar_Pervasives_Native_uu___is_Some__bool(FStar_Pervasives_Native_option__bool projectee)
{
  if (projectee.tag == FStar_Pervasives_Native_Some)
    return true;
  else
    return false;
}

typedef struct K___CBOR_Pulse_Raw_Type_cbor_raw_CBOR_Pulse_Raw_Type_cbor_raw_s
{
  cbor_raw fst;
  cbor_raw snd;
}
K___CBOR_Pulse_Raw_Type_cbor_raw_CBOR_Pulse_Raw_Type_cbor_raw;

bool CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(cbor_raw x1, cbor_raw x2)
{
  uint8_t mt1 = CBOR_Pulse_Raw_Compare_impl_major_type(x1);
  if (mt1 != CBOR_Pulse_Raw_Compare_impl_major_type(x2))
    return false;
  else if (mt1 == CBOR_MAJOR_TYPE_SIMPLE_VALUE)
  {
    uint8_t w1;
    if (x1.tag == CBOR_Case_Simple)
      w1 = x1.case_CBOR_Case_Simple;
    else
      w1 = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
    uint8_t ite;
    if (x2.tag == CBOR_Case_Simple)
      ite = x2.case_CBOR_Case_Simple;
    else
      ite = KRML_EABORT(uint8_t, "unreachable (pattern matches are exhaustive in F*)");
    return w1 == ite;
  }
  else if (mt1 == CBOR_MAJOR_TYPE_UINT64 || mt1 == CBOR_MAJOR_TYPE_NEG_INT64)
  {
    CBOR_Spec_Raw_Base_raw_uint64 w1;
    if (x1.tag == CBOR_Case_Int)
    {
      cbor_int c_ = x1.case_CBOR_Case_Int;
      w1 = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = c_.cbor_int_size, .value = c_.cbor_int_value });
    }
    else
      w1 =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    CBOR_Spec_Raw_Base_raw_uint64 ite;
    if (x2.tag == CBOR_Case_Int)
    {
      cbor_int c_ = x2.case_CBOR_Case_Int;
      ite =
        ((CBOR_Spec_Raw_Base_raw_uint64){ .size = c_.cbor_int_size, .value = c_.cbor_int_value });
    }
    else
      ite =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    return w1.value == ite.value;
  }
  else if (mt1 == CBOR_MAJOR_TYPE_BYTE_STRING || mt1 == CBOR_MAJOR_TYPE_TEXT_STRING)
  {
    CBOR_Spec_Raw_Base_raw_uint64 len1;
    if (x1.tag == CBOR_Case_String)
    {
      cbor_string c_ = x1.case_CBOR_Case_String;
      len1 =
        (
          (CBOR_Spec_Raw_Base_raw_uint64){
            .size = c_.cbor_string_size,
            .value = (uint64_t)Pulse_Lib_Slice_len__uint8_t(c_.cbor_string_ptr)
          }
        );
    }
    else
      len1 =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    CBOR_Spec_Raw_Base_raw_uint64 ite0;
    if (x2.tag == CBOR_Case_String)
    {
      cbor_string c_ = x2.case_CBOR_Case_String;
      ite0 =
        (
          (CBOR_Spec_Raw_Base_raw_uint64){
            .size = c_.cbor_string_size,
            .value = (uint64_t)Pulse_Lib_Slice_len__uint8_t(c_.cbor_string_ptr)
          }
        );
    }
    else
      ite0 =
        KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
          "unreachable (pattern matches are exhaustive in F*)");
    if (len1.value != ite0.value)
      return false;
    else
    {
      Pulse_Lib_Slice_slice__uint8_t w1;
      if (x1.tag == CBOR_Case_String)
        w1 = x1.case_CBOR_Case_String.cbor_string_ptr;
      else
        w1 =
          KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
            "unreachable (pattern matches are exhaustive in F*)");
      Pulse_Lib_Slice_slice__uint8_t ite;
      if (x2.tag == CBOR_Case_String)
        ite = x2.case_CBOR_Case_String.cbor_string_ptr;
      else
        ite =
          KRML_EABORT(Pulse_Lib_Slice_slice__uint8_t,
            "unreachable (pattern matches are exhaustive in F*)");
      return CBOR_Pulse_Raw_Compare_Bytes_lex_compare_bytes(w1, ite) == (int16_t)0;
    }
  }
  else if (mt1 == CBOR_MAJOR_TYPE_TAGGED)
  {
    K___CBOR_Pulse_Raw_Type_cbor_raw_CBOR_Pulse_Raw_Type_cbor_raw scrut = { .fst = x1, .snd = x2 };
    bool ite0;
    if
    (scrut.fst.tag == CBOR_Case_Serialized_Tagged && scrut.snd.tag == CBOR_Case_Serialized_Tagged)
      ite0 = true;
    else
      ite0 = false;
    if (ite0)
      if (x1.tag == CBOR_Case_Serialized_Tagged)
      {
        cbor_serialized cs1 = x1.case_CBOR_Case_Serialized_Tagged;
        if (x2.tag == CBOR_Case_Serialized_Tagged)
          return
            CBOR_Pulse_Raw_Format_Nondet_Compare_cbor_match_equal_serialized_tagged(cs1,
              x2.case_CBOR_Case_Serialized_Tagged);
        else
        {
          KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
            __FILE__,
            __LINE__,
            "unreachable (pattern matches are exhaustive in F*)");
          KRML_HOST_EXIT(255U);
        }
      }
      else
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
          __FILE__,
          __LINE__,
          "unreachable (pattern matches are exhaustive in F*)");
        KRML_HOST_EXIT(255U);
      }
    else
    {
      CBOR_Spec_Raw_Base_raw_uint64 tag1;
      if (x1.tag == CBOR_Case_Tagged)
        tag1 = x1.case_CBOR_Case_Tagged.cbor_tagged_tag;
      else if (x1.tag == CBOR_Case_Serialized_Tagged)
        tag1 = x1.case_CBOR_Case_Serialized_Tagged.cbor_serialized_header;
      else
        tag1 =
          KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
            "unreachable (pattern matches are exhaustive in F*)");
      CBOR_Spec_Raw_Base_raw_uint64 ite;
      if (x2.tag == CBOR_Case_Tagged)
        ite = x2.case_CBOR_Case_Tagged.cbor_tagged_tag;
      else if (x2.tag == CBOR_Case_Serialized_Tagged)
        ite = x2.case_CBOR_Case_Serialized_Tagged.cbor_serialized_header;
      else
        ite =
          KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
            "unreachable (pattern matches are exhaustive in F*)");
      if (tag1.value != ite.value)
        return false;
      else
      {
        cbor_raw w1 = CBOR_Pulse_Raw_Read_cbor_match_tagged_get_payload(x1);
        return
          CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(w1,
            CBOR_Pulse_Raw_Read_cbor_match_tagged_get_payload(x2));
      }
    }
  }
  else if (mt1 == CBOR_MAJOR_TYPE_ARRAY)
  {
    K___CBOR_Pulse_Raw_Type_cbor_raw_CBOR_Pulse_Raw_Type_cbor_raw scrut = { .fst = x1, .snd = x2 };
    bool ite0;
    if (scrut.fst.tag == CBOR_Case_Serialized_Array && scrut.snd.tag == CBOR_Case_Serialized_Array)
      ite0 = true;
    else
      ite0 = false;
    if (ite0)
      if (x1.tag == CBOR_Case_Serialized_Array)
      {
        cbor_serialized cs1 = x1.case_CBOR_Case_Serialized_Array;
        if (x2.tag == CBOR_Case_Serialized_Array)
          return
            CBOR_Pulse_Raw_Format_Nondet_Compare_cbor_match_compare_serialized_array(cs1,
              x2.case_CBOR_Case_Serialized_Array);
        else
        {
          KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
            __FILE__,
            __LINE__,
            "unreachable (pattern matches are exhaustive in F*)");
          KRML_HOST_EXIT(255U);
        }
      }
      else
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
          __FILE__,
          __LINE__,
          "unreachable (pattern matches are exhaustive in F*)");
        KRML_HOST_EXIT(255U);
      }
    else
    {
      CBOR_Spec_Raw_Base_raw_uint64 len1;
      if (x1.tag == CBOR_Case_Array)
      {
        cbor_array c_ = x1.case_CBOR_Case_Array;
        len1 =
          (
            (CBOR_Spec_Raw_Base_raw_uint64){
              .size = c_.cbor_array_length_size,
              .value = (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(c_.cbor_array_ptr)
            }
          );
      }
      else if (x1.tag == CBOR_Case_Serialized_Array)
        len1 = x1.case_CBOR_Case_Serialized_Array.cbor_serialized_header;
      else
        len1 =
          KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
            "unreachable (pattern matches are exhaustive in F*)");
      CBOR_Spec_Raw_Base_raw_uint64 ite;
      if (x2.tag == CBOR_Case_Array)
      {
        cbor_array c_ = x2.case_CBOR_Case_Array;
        ite =
          (
            (CBOR_Spec_Raw_Base_raw_uint64){
              .size = c_.cbor_array_length_size,
              .value = (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(c_.cbor_array_ptr)
            }
          );
      }
      else if (x2.tag == CBOR_Case_Serialized_Array)
        ite = x2.case_CBOR_Case_Serialized_Array.cbor_serialized_header;
      else
        ite =
          KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
            "unreachable (pattern matches are exhaustive in F*)");
      if (len1.value != ite.value)
        return false;
      else
      {
        CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
        pi1 = CBOR_Pulse_Raw_Read_cbor_array_iterator_init(x1);
        CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
        pi2 = CBOR_Pulse_Raw_Read_cbor_array_iterator_init(x2);
        bool pres = true;
        bool cond;
        if (pres)
          cond = !CBOR_Pulse_Raw_Read_cbor_array_iterator_is_empty(pi1);
        else
          cond = false;
        while (cond)
        {
          cbor_raw y1 = CBOR_Pulse_Raw_Read_cbor_array_iterator_next(&pi1);
          pres =
            CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(y1,
              CBOR_Pulse_Raw_Read_cbor_array_iterator_next(&pi2));
          bool ite;
          if (pres)
            ite = !CBOR_Pulse_Raw_Read_cbor_array_iterator_is_empty(pi1);
          else
            ite = false;
          cond = ite;
        }
        return pres;
      }
    }
  }
  else
  {
    K___CBOR_Pulse_Raw_Type_cbor_raw_CBOR_Pulse_Raw_Type_cbor_raw scrut = { .fst = x1, .snd = x2 };
    bool ite;
    if (scrut.fst.tag == CBOR_Case_Serialized_Map && scrut.snd.tag == CBOR_Case_Serialized_Map)
      ite = true;
    else
      ite = false;
    if (ite)
      if (x1.tag == CBOR_Case_Serialized_Map)
      {
        cbor_serialized cs1 = x1.case_CBOR_Case_Serialized_Map;
        if (x2.tag == CBOR_Case_Serialized_Map)
          return
            CBOR_Pulse_Raw_Format_Nondet_Compare_cbor_match_compare_serialized_map(cs1,
              x2.case_CBOR_Case_Serialized_Map);
        else
        {
          KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
            __FILE__,
            __LINE__,
            "unreachable (pattern matches are exhaustive in F*)");
          KRML_HOST_EXIT(255U);
        }
      }
      else
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
          __FILE__,
          __LINE__,
          "unreachable (pattern matches are exhaustive in F*)");
        KRML_HOST_EXIT(255U);
      }
    else
    {
      CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
      i1 = CBOR_Pulse_Raw_Read_cbor_map_iterator_init(x1);
      CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
      i2 = CBOR_Pulse_Raw_Read_cbor_map_iterator_init(x2);
      CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry pi2 = i1;
      bool pres0 = true;
      bool cond0;
      if (pres0)
        cond0 = !CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(pi2);
      else
        cond0 = false;
      while (cond0)
      {
        cbor_map_entry x21 = CBOR_Pulse_Raw_Read_cbor_map_iterator_next(&pi2);
        CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry pi1 = i2;
        FStar_Pervasives_Native_option__bool pres1 = { .tag = FStar_Pervasives_Native_None };
        bool cond;
        if (FStar_Pervasives_Native_uu___is_Some__bool(pres1))
          cond = false;
        else
          cond = !CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(pi1);
        while (cond)
        {
          cbor_map_entry x11 = CBOR_Pulse_Raw_Read_cbor_map_iterator_next(&pi1);
          if
          (
            CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(x21.cbor_map_entry_key,
              x11.cbor_map_entry_key)
          )
            pres1 =
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(x21.cbor_map_entry_value,
                    x11.cbor_map_entry_value)
                }
              );
          bool ite;
          if (FStar_Pervasives_Native_uu___is_Some__bool(pres1))
            ite = false;
          else
            ite = !CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(pi1);
          cond = ite;
        }
        pres0 =
          __eq__FStar_Pervasives_Native_option__bool(pres1,
            (
              (FStar_Pervasives_Native_option__bool){
                .tag = FStar_Pervasives_Native_Some,
                .v = true
              }
            ));
        bool ite;
        if (pres0)
          ite = !CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(pi2);
        else
          ite = false;
        cond0 = ite;
      }
      if (!pres0)
        return false;
      else
      {
        CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry pi2 = i2;
        bool pres = true;
        bool cond0;
        if (pres)
          cond0 = !CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(pi2);
        else
          cond0 = false;
        while (cond0)
        {
          cbor_map_entry x21 = CBOR_Pulse_Raw_Read_cbor_map_iterator_next(&pi2);
          CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry pi1 = i1;
          FStar_Pervasives_Native_option__bool pres1 = { .tag = FStar_Pervasives_Native_None };
          bool cond;
          if (FStar_Pervasives_Native_uu___is_Some__bool(pres1))
            cond = false;
          else
            cond = !CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(pi1);
          while (cond)
          {
            cbor_map_entry x11 = CBOR_Pulse_Raw_Read_cbor_map_iterator_next(&pi1);
            if
            (
              CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(x21.cbor_map_entry_key,
                x11.cbor_map_entry_key)
            )
              pres1 =
                (
                  (FStar_Pervasives_Native_option__bool){
                    .tag = FStar_Pervasives_Native_Some,
                    .v = CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(x21.cbor_map_entry_value,
                      x11.cbor_map_entry_value)
                  }
                );
            bool ite;
            if (FStar_Pervasives_Native_uu___is_Some__bool(pres1))
              ite = false;
            else
              ite = !CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(pi1);
            cond = ite;
          }
          pres =
            __eq__FStar_Pervasives_Native_option__bool(pres1,
              (
                (FStar_Pervasives_Native_option__bool){
                  .tag = FStar_Pervasives_Native_Some,
                  .v = true
                }
              ));
          bool ite;
          if (pres)
            ite = !CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(pi2);
          else
            ite = false;
          cond0 = ite;
        }
        return pres;
      }
    }
  }
}

static bool
CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_no_setoid_repeats(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry x
)
{
  size_t pn1 = (size_t)0U;
  bool pres = true;
  bool cond0;
  if (pres)
  {
    size_t __anf01 = pn1;
    cond0 = __anf01 < Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(x);
  }
  else
    cond0 = false;
  while (cond0)
  {
    size_t n1 = pn1;
    cbor_map_entry x1 = Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_map_entry(x, n1);
    size_t n2 = n1 + (size_t)1U;
    pn1 = n2;
    size_t pn2 = n2;
    bool cond;
    if (pres)
    {
      size_t __anf01 = pn2;
      cond = __anf01 < Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(x);
    }
    else
      cond = false;
    while (cond)
    {
      size_t n21 = pn2;
      pres =
        !CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(x1.cbor_map_entry_key,
          Pulse_Lib_Slice_op_Array_Access__CBOR_Pulse_Raw_Type_cbor_map_entry(x,
            n21).cbor_map_entry_key);
      pn2 = n21 + (size_t)1U;
      bool ite;
      if (pres)
      {
        size_t __anf01 = pn2;
        ite = __anf01 < Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(x);
      }
      else
        ite = false;
      cond = ite;
    }
    bool ite;
    if (pres)
    {
      size_t __anf01 = pn1;
      ite = __anf01 < Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(x);
    }
    else
      ite = false;
    cond0 = ite;
  }
  return pres;
}

static size_t
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_validate(
  FStar_Pervasives_Native_option__size_t map_key_bound,
  bool strict_check,
  Pulse_Lib_Slice_slice__uint8_t input
)
{
  return
    CBOR_Pulse_Raw_Format_Nondet_Validate_cbor_validate_nondet(map_key_bound,
      strict_check,
      input);
}

static cbor_raw
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_parse_valid(
  Pulse_Lib_Slice_slice__uint8_t input,
  size_t len
)
{
  return CBOR_Pulse_Raw_Format_Parse_cbor_parse(input, len);
}

static FStar_Pervasives_Native_option__size_t
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_serialize(
  cbor_raw x,
  Pulse_Lib_Slice_slice__uint8_t output
)
{
  size_t
  len = CBOR_Pulse_Raw_Format_Serialize_cbor_size(x, Pulse_Lib_Slice_len__uint8_t(output));
  if (len == (size_t)0U)
    return ((FStar_Pervasives_Native_option__size_t){ .tag = FStar_Pervasives_Native_None });
  else
    return
      (
        (FStar_Pervasives_Native_option__size_t){
          .tag = FStar_Pervasives_Native_Some,
          .v = CBOR_Pulse_Raw_Format_Serialize_cbor_serialize(x,
            Pulse_Lib_Slice_split__uint8_t(output, len).fst)
        }
      );
}

static uint8_t CBOR_Pulse_API_Nondet_Rust_cbor_nondet_major_type(cbor_raw x)
{
  return CBOR_Pulse_Raw_Compare_impl_major_type(x);
}

static uint8_t CBOR_Pulse_API_Nondet_Rust_cbor_nondet_read_simple_value(cbor_raw x)
{
  if (x.tag == CBOR_Case_Simple)
    return x.case_CBOR_Case_Simple;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static uint64_t CBOR_Pulse_API_Nondet_Rust_cbor_nondet_read_uint64(cbor_raw x)
{
  CBOR_Spec_Raw_Base_raw_uint64 ite;
  if (x.tag == CBOR_Case_Int)
  {
    cbor_int c_ = x.case_CBOR_Case_Int;
    ite = ((CBOR_Spec_Raw_Base_raw_uint64){ .size = c_.cbor_int_size, .value = c_.cbor_int_value });
  }
  else
    ite =
      KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
        "unreachable (pattern matches are exhaustive in F*)");
  return ite.value;
}

static uint64_t CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_string_length(cbor_raw x)
{
  CBOR_Spec_Raw_Base_raw_uint64 ite;
  if (x.tag == CBOR_Case_String)
  {
    cbor_string c_ = x.case_CBOR_Case_String;
    ite =
      (
        (CBOR_Spec_Raw_Base_raw_uint64){
          .size = c_.cbor_string_size,
          .value = (uint64_t)Pulse_Lib_Slice_len__uint8_t(c_.cbor_string_ptr)
        }
      );
  }
  else
    ite =
      KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
        "unreachable (pattern matches are exhaustive in F*)");
  return ite.value;
}

static Pulse_Lib_Slice_slice__uint8_t
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_string(cbor_raw x)
{
  if (x.tag == CBOR_Case_String)
    return x.case_CBOR_Case_String.cbor_string_ptr;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static uint64_t CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_tagged_tag(cbor_raw x)
{
  CBOR_Spec_Raw_Base_raw_uint64 ite;
  if (x.tag == CBOR_Case_Tagged)
    ite = x.case_CBOR_Case_Tagged.cbor_tagged_tag;
  else if (x.tag == CBOR_Case_Serialized_Tagged)
    ite = x.case_CBOR_Case_Serialized_Tagged.cbor_serialized_header;
  else
    ite =
      KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
        "unreachable (pattern matches are exhaustive in F*)");
  return ite.value;
}

static cbor_raw CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_tagged_payload(cbor_raw x)
{
  return CBOR_Pulse_Raw_Read_cbor_match_tagged_get_payload(x);
}

static uint64_t CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_array_length(cbor_raw x)
{
  CBOR_Spec_Raw_Base_raw_uint64 ite;
  if (x.tag == CBOR_Case_Array)
  {
    cbor_array c_ = x.case_CBOR_Case_Array;
    ite =
      (
        (CBOR_Spec_Raw_Base_raw_uint64){
          .size = c_.cbor_array_length_size,
          .value = (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(c_.cbor_array_ptr)
        }
      );
  }
  else if (x.tag == CBOR_Case_Serialized_Array)
    ite = x.case_CBOR_Case_Serialized_Array.cbor_serialized_header;
  else
    ite =
      KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
        "unreachable (pattern matches are exhaustive in F*)");
  return ite.value;
}

static CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_start(cbor_raw x)
{
  return CBOR_Pulse_Raw_Read_cbor_array_iterator_init(x);
}

static bool
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x
)
{
  return CBOR_Pulse_Raw_Read_cbor_array_iterator_is_empty(x);
}

static uint64_t
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_length(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x
)
{
  return CBOR_Pulse_Raw_Read_cbor_array_iterator_length(x);
}

static cbor_raw
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw *x
)
{
  return CBOR_Pulse_Raw_Read_cbor_array_iterator_next(x);
}

static CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_truncate(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x,
  uint64_t len
)
{
  return CBOR_Pulse_Raw_Read_cbor_array_iterator_truncate(x, len);
}

static cbor_raw CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_array_item(cbor_raw x, uint64_t i)
{
  return CBOR_Pulse_Raw_Read_cbor_array_item(x, i);
}

static uint64_t CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_map_length(cbor_raw x)
{
  CBOR_Spec_Raw_Base_raw_uint64 ite;
  if (x.tag == CBOR_Case_Map)
  {
    cbor_map c_ = x.case_CBOR_Case_Map;
    ite =
      (
        (CBOR_Spec_Raw_Base_raw_uint64){
          .size = c_.cbor_map_length_size,
          .value = (uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(c_.cbor_map_ptr)
        }
      );
  }
  else if (x.tag == CBOR_Case_Serialized_Map)
    ite = x.case_CBOR_Case_Serialized_Map.cbor_serialized_header;
  else
    ite =
      KRML_EABORT(CBOR_Spec_Raw_Base_raw_uint64,
        "unreachable (pattern matches are exhaustive in F*)");
  return ite.value;
}

static CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_start(cbor_raw x)
{
  return CBOR_Pulse_Raw_Read_cbor_map_iterator_init(x);
}

static bool
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry x
)
{
  return CBOR_Pulse_Raw_Read_cbor_map_iterator_is_empty(x);
}

static cbor_map_entry
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry *x
)
{
  return CBOR_Pulse_Raw_Read_cbor_map_iterator_next(x);
}

static cbor_raw CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_entry_key(cbor_map_entry x2)
{
  return x2.cbor_map_entry_key;
}

static cbor_raw CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_entry_value(cbor_map_entry x2)
{
  return x2.cbor_map_entry_value;
}

static bool CBOR_Pulse_API_Nondet_Rust_cbor_nondet_equal(cbor_raw x1, cbor_raw x2)
{
  return CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(x1, x2);
}

static bool
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_get(cbor_raw x, cbor_raw k, cbor_raw *dest)
{
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
  i = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_start(x);
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry pi = i;
  bool pres = false;
  bool pcont = !CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_is_empty(i);
  while (pcont && !pres)
  {
    cbor_map_entry y = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_next(&pi);
    if (CBOR_Pulse_API_Nondet_Rust_cbor_nondet_equal(y.cbor_map_entry_key, k))
    {
      *dest = y.cbor_map_entry_value;
      pres = true;
    }
    else
      pcont = !CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_is_empty(pi);
  }
  return pres;
}

static cbor_raw CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_simple_value(uint8_t v)
{
  return ((cbor_raw){ .tag = CBOR_Case_Simple, { .case_CBOR_Case_Simple = v } });
}

static cbor_raw CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_int64(uint8_t ty, uint64_t v)
{
  return
    (
      (cbor_raw){
        .tag = CBOR_Case_Int,
        {
          .case_CBOR_Case_Int = {
            .cbor_int_type = ty,
            .cbor_int_size = CBOR_Spec_Raw_Optimal_mk_raw_uint64(v).size,
            .cbor_int_value = CBOR_Spec_Raw_Optimal_mk_raw_uint64(v).value
          }
        }
      }
    );
}

static cbor_raw
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_string(uint8_t ty, Pulse_Lib_Slice_slice__uint8_t s)
{
  return
    CBOR_Pulse_Raw_Match_cbor_raw_reset_perm_tot((
        (cbor_raw){
          .tag = CBOR_Case_String,
          {
            .case_CBOR_Case_String = {
              .cbor_string_type = ty,
              .cbor_string_size = CBOR_Spec_Raw_Optimal_mk_raw_uint64((uint64_t)Pulse_Lib_Slice_len__uint8_t(s)).size,
              .cbor_string_ptr = s
            }
          }
        }
      ));
}

static cbor_raw CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_tagged(uint64_t tag, cbor_raw *r)
{
  return
    CBOR_Pulse_Raw_Match_cbor_raw_reset_perm_tot((
        (cbor_raw){
          .tag = CBOR_Case_Tagged,
          {
            .case_CBOR_Case_Tagged = {
              .cbor_tagged_tag = CBOR_Spec_Raw_Optimal_mk_raw_uint64(tag),
              .cbor_tagged_ptr = r
            }
          }
        }
      ));
}

static cbor_raw
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_array(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw a
)
{
  return
    CBOR_Pulse_Raw_Match_cbor_raw_reset_perm_tot((
        (cbor_raw){
          .tag = CBOR_Case_Array,
          {
            .case_CBOR_Case_Array = {
              .cbor_array_length_size = CBOR_Spec_Raw_Optimal_mk_raw_uint64((uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_raw(a)).size,
              .cbor_array_ptr = a
            }
          }
        }
      ));
}

static cbor_map_entry
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_map_entry(cbor_raw xk, cbor_raw xv)
{
  cbor_raw xk_ = CBOR_Pulse_Raw_Match_cbor_raw_reset_perm_tot(xk);
  return
    (
      (cbor_map_entry){
        .cbor_map_entry_key = xk_,
        .cbor_map_entry_value = CBOR_Pulse_Raw_Match_cbor_raw_reset_perm_tot(xv)
      }
    );
}

static bool
CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_map_gen(
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry a,
  cbor_raw *dest
)
{
  if
  (Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(a) > (size_t)18446744073709551615ULL)
    return false;
  else if (CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_no_setoid_repeats(a))
  {
    *dest =
      CBOR_Pulse_Raw_Match_cbor_raw_reset_perm_tot((
          (cbor_raw){
            .tag = CBOR_Case_Map,
            {
              .case_CBOR_Case_Map = {
                .cbor_map_length_size = CBOR_Spec_Raw_Optimal_mk_raw_uint64((uint64_t)Pulse_Lib_Slice_len__CBOR_Pulse_Raw_Type_cbor_map_entry(a)).size,
                .cbor_map_ptr = a
              }
            }
          }
        ));
    return true;
  }
  else
    return false;
}

static Pulse_Lib_Slice_slice__uint8_t
Pulse_Lib_Slice_arrayptr_to_slice_intro__uint8_t(uint8_t *a, size_t alen)
{
  return ((Pulse_Lib_Slice_slice__uint8_t){ .elt = a, .len = alen });
}

bool
cbor_nondet_parse(
  bool check_map_key_bound,
  size_t map_key_bound,
  uint8_t **pinput,
  size_t *plen,
  cbor_raw *dest
)
{
  if (pinput == NULL || plen == NULL || dest == NULL)
    return false;
  else
  {
    uint8_t *input1 = *pinput;
    if (*pinput == NULL)
      return false;
    else
    {
      size_t len1 = *plen;
      Pulse_Lib_Slice_slice__uint8_t
      s = Pulse_Lib_Slice_arrayptr_to_slice_intro__uint8_t(input1, len1);
      FStar_Pervasives_Native_option__size_t ite;
      if (check_map_key_bound)
        ite =
          (
            (FStar_Pervasives_Native_option__size_t){
              .tag = FStar_Pervasives_Native_Some,
              .v = map_key_bound
            }
          );
      else
        ite = ((FStar_Pervasives_Native_option__size_t){ .tag = FStar_Pervasives_Native_None });
      size_t consume = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_validate(ite, check_map_key_bound, s);
      if (consume == (size_t)0U)
        return false;
      else
      {
        *pinput = input1 + consume;
        *plen = len1 - consume;
        *dest =
          CBOR_Pulse_API_Nondet_Rust_cbor_nondet_parse_valid(Pulse_Lib_Slice_arrayptr_to_slice_intro__uint8_t(input1,
              consume),
            consume);
        return true;
      }
    }
  }
}

size_t cbor_nondet_serialize(cbor_raw x, uint8_t *output, size_t len)
{
  if (output == NULL)
    return (size_t)0U;
  else
  {
    FStar_Pervasives_Native_option__size_t
    scrut =
      CBOR_Pulse_API_Nondet_Rust_cbor_nondet_serialize(x,
        Pulse_Lib_Slice_arrayptr_to_slice_intro__uint8_t(output, len));
    if (scrut.tag == FStar_Pervasives_Native_None)
      return (size_t)0U;
    else if (scrut.tag == FStar_Pervasives_Native_Some)
      return scrut.v;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
}

uint8_t cbor_nondet_major_type(cbor_raw x)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_major_type(x);
}

bool cbor_nondet_read_simple_value(cbor_raw x, uint8_t *dest)
{
  if (dest == NULL)
    return false;
  else if (cbor_nondet_major_type(x) != CBOR_MAJOR_TYPE_SIMPLE_VALUE)
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_read_simple_value(x);
    return true;
  }
}

bool cbor_nondet_read_uint64(cbor_raw x, uint64_t *dest)
{
  if (dest == NULL)
    return false;
  else
  {
    uint8_t ty = cbor_nondet_major_type(x);
    if (ty != CBOR_MAJOR_TYPE_UINT64 && ty != CBOR_MAJOR_TYPE_NEG_INT64)
      return false;
    else
    {
      *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_read_uint64(x);
      return true;
    }
  }
}

static uint8_t
*Pulse_Lib_Slice_slice_to_arrayptr_intro__uint8_t(Pulse_Lib_Slice_slice__uint8_t s)
{
  return s.elt;
}

bool cbor_nondet_get_string(cbor_raw x, uint8_t **dest, uint64_t *dlen)
{
  if (dest == NULL || dlen == NULL)
    return false;
  else
  {
    uint8_t ty = cbor_nondet_major_type(x);
    if (ty != CBOR_MAJOR_TYPE_BYTE_STRING && ty != CBOR_MAJOR_TYPE_TEXT_STRING)
      return false;
    else
    {
      uint64_t len = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_string_length(x);
      uint8_t
      *res =
        Pulse_Lib_Slice_slice_to_arrayptr_intro__uint8_t(CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_string(x));
      *dlen = len;
      *dest = res;
      return true;
    }
  }
}

bool cbor_nondet_get_tagged(cbor_raw x, cbor_raw *dest, uint64_t *dtag)
{
  if (dest == NULL || dtag == NULL)
    return false;
  else if (cbor_nondet_major_type(x) != CBOR_MAJOR_TYPE_TAGGED)
    return false;
  else
  {
    uint64_t tag = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_tagged_tag(x);
    cbor_raw res = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_tagged_payload(x);
    *dtag = tag;
    *dest = res;
    return true;
  }
}

bool cbor_nondet_get_array_length(cbor_raw x, uint64_t *dest)
{
  if (dest == NULL)
    return false;
  else if (cbor_nondet_major_type(x) != CBOR_MAJOR_TYPE_ARRAY)
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_array_length(x);
    return true;
  }
}

bool
cbor_nondet_array_iterator_start(
  cbor_raw x,
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw *dest
)
{
  if (dest == NULL)
    return false;
  else if (cbor_nondet_major_type(x) != CBOR_MAJOR_TYPE_ARRAY)
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_start(x);
    return true;
  }
}

bool
cbor_nondet_array_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x
)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_is_empty(x);
}

uint64_t
cbor_nondet_array_iterator_length(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x
)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_length(x);
}

bool
cbor_nondet_array_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw *x,
  cbor_raw *dest
)
{
  if (x == NULL || dest == NULL)
    return false;
  else if (cbor_nondet_array_iterator_is_empty(*x))
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_next(x);
    return true;
  }
}

CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
cbor_nondet_array_iterator_truncate(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x,
  uint64_t len
)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_array_iterator_truncate(x, len);
}

bool cbor_nondet_get_array_item(cbor_raw x, uint64_t i, cbor_raw *dest)
{
  if (dest == NULL)
    return false;
  else if (cbor_nondet_major_type(x) != CBOR_MAJOR_TYPE_ARRAY)
    return false;
  else if (CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_array_length(x) <= i)
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_array_item(x, i);
    return true;
  }
}

bool cbor_nondet_get_map_length(cbor_raw x, uint64_t *dest)
{
  if (dest == NULL)
    return false;
  else if (cbor_nondet_major_type(x) != CBOR_MAJOR_TYPE_MAP)
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_get_map_length(x);
    return true;
  }
}

bool
cbor_nondet_map_iterator_start(
  cbor_raw x,
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry *dest
)
{
  if (dest == NULL)
    return false;
  else if (cbor_nondet_major_type(x) != CBOR_MAJOR_TYPE_MAP)
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_start(x);
    return true;
  }
}

bool
cbor_nondet_map_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry x
)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_is_empty(x);
}

cbor_raw cbor_nondet_map_entry_key(cbor_map_entry x)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_entry_key(x);
}

cbor_raw cbor_nondet_map_entry_value(cbor_map_entry x)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_entry_value(x);
}

bool
cbor_nondet_map_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry *x,
  cbor_raw *dest_key,
  cbor_raw *dest_value
)
{
  if (x == NULL || dest_key == NULL || dest_value == NULL)
    return false;
  else if (cbor_nondet_map_iterator_is_empty(*x))
    return false;
  else
  {
    cbor_map_entry res = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_iterator_next(x);
    cbor_raw res_key = cbor_nondet_map_entry_key(res);
    cbor_raw res_value = cbor_nondet_map_entry_value(res);
    *dest_key = res_key;
    *dest_value = res_value;
    return true;
  }
}

bool cbor_nondet_equal(cbor_raw x1, cbor_raw x2)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_equal(x1, x2);
}

bool cbor_nondet_map_get(cbor_raw x, cbor_raw k, cbor_raw *dest)
{
  if (dest == NULL)
    return false;
  else if (cbor_nondet_major_type(x) != CBOR_MAJOR_TYPE_MAP)
    return false;
  else
    return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_map_get(x, k, dest);
}

bool cbor_nondet_mk_simple_value(uint8_t v, cbor_raw *dest)
{
  if
  (
    dest == NULL || !(v <= MAX_SIMPLE_VALUE_ADDITIONAL_INFO || MIN_SIMPLE_VALUE_LONG_ARGUMENT <= v)
  )
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_simple_value(v);
    return true;
  }
}

cbor_raw cbor_nondet_mk_uint64(uint64_t v)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_int64(CBOR_MAJOR_TYPE_UINT64, v);
}

cbor_raw cbor_nondet_mk_neg_int64(uint64_t v)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_int64(CBOR_MAJOR_TYPE_NEG_INT64, v);
}

bool cbor_nondet_mk_byte_string(uint8_t *a, uint64_t len, cbor_raw *dest)
{
  bool __anf0 = a == NULL;
  if (__anf0 || dest == NULL)
    return false;
  else
  {
    Pulse_Lib_Slice_slice__uint8_t
    s = Pulse_Lib_Slice_arrayptr_to_slice_intro__uint8_t(a, (size_t)len);
    bool ite;
    if (CBOR_MAJOR_TYPE_BYTE_STRING == CBOR_MAJOR_TYPE_TEXT_STRING)
      ite = CBOR_Pulse_Raw_EverParse_UTF8_impl_correct(s);
    else
      ite = true;
    if (ite)
    {
      *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_string(CBOR_MAJOR_TYPE_BYTE_STRING, s);
      return true;
    }
    else
      return false;
  }
}

bool cbor_nondet_mk_text_string(uint8_t *a, uint64_t len, cbor_raw *dest)
{
  bool __anf0 = a == NULL;
  if (__anf0 || dest == NULL)
    return false;
  else
  {
    Pulse_Lib_Slice_slice__uint8_t
    s = Pulse_Lib_Slice_arrayptr_to_slice_intro__uint8_t(a, (size_t)len);
    if (CBOR_Pulse_Raw_EverParse_UTF8_impl_correct(s))
    {
      *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_string(CBOR_MAJOR_TYPE_TEXT_STRING, s);
      return true;
    }
    else
      return false;
  }
}

bool cbor_nondet_mk_tagged(uint64_t tag, cbor_raw *r, cbor_raw *dest)
{
  if (r == NULL || dest == NULL)
    return false;
  else
  {
    *dest = CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_tagged(tag, r);
    return true;
  }
}

static Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw
Pulse_Lib_Slice_arrayptr_to_slice_intro__CBOR_Pulse_Raw_Type_cbor_raw(cbor_raw *a, size_t alen)
{
  return ((Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw){ .elt = a, .len = alen });
}

bool cbor_nondet_mk_array(cbor_raw *a, uint64_t len, cbor_raw *dest)
{
  bool __anf0 = a == NULL;
  if (__anf0 || dest == NULL)
    return false;
  else
  {
    *dest =
      CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_array(Pulse_Lib_Slice_arrayptr_to_slice_intro__CBOR_Pulse_Raw_Type_cbor_raw(a,
          (size_t)len));
    return true;
  }
}

cbor_map_entry cbor_nondet_mk_map_entry(cbor_raw xk, cbor_raw xv)
{
  return CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_map_entry(xk, xv);
}

static Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry
Pulse_Lib_Slice_arrayptr_to_slice_intro__CBOR_Pulse_Raw_Type_cbor_map_entry(
  cbor_map_entry *a,
  size_t alen
)
{
  return ((Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry){ .elt = a, .len = alen });
}

bool cbor_nondet_mk_map(cbor_map_entry *a, uint64_t len, cbor_raw *dest)
{
  bool __anf0 = a == NULL;
  if (__anf0 || dest == NULL)
    return false;
  else
    return
      CBOR_Pulse_API_Nondet_Rust_cbor_nondet_mk_map_gen(Pulse_Lib_Slice_arrayptr_to_slice_intro__CBOR_Pulse_Raw_Type_cbor_map_entry(a,
          (size_t)len),
        dest);
}

