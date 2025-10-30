

#ifndef CBORNondet_H
#define CBORNondet_H

#include "krmllib.h"

typedef struct CBOR_Spec_Raw_Base_raw_uint64_s
{
  uint8_t size;
  uint64_t value;
}
CBOR_Spec_Raw_Base_raw_uint64;

typedef struct Pulse_Lib_Slice_slice__uint8_t_s
{
  uint8_t *elt;
  size_t len;
}
Pulse_Lib_Slice_slice__uint8_t;

typedef struct CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator_s
{
  Pulse_Lib_Slice_slice__uint8_t s;
  uint64_t len;
}
CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator;

typedef struct cbor_string_s
{
  uint8_t cbor_string_type;
  uint8_t cbor_string_size;
  Pulse_Lib_Slice_slice__uint8_t cbor_string_ptr;
}
cbor_string;

typedef struct cbor_serialized_s
{
  CBOR_Spec_Raw_Base_raw_uint64 cbor_serialized_header;
  Pulse_Lib_Slice_slice__uint8_t cbor_serialized_payload;
}
cbor_serialized;

typedef struct cbor_raw_s cbor_raw;

typedef struct cbor_tagged_s
{
  CBOR_Spec_Raw_Base_raw_uint64 cbor_tagged_tag;
  cbor_raw *cbor_tagged_ptr;
}
cbor_tagged;

typedef struct cbor_raw_s cbor_raw;

typedef struct cbor_raw_s cbor_raw;

typedef struct Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw_s
{
  cbor_raw *elt;
  size_t len;
}
Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw;

typedef struct cbor_array_s
{
  uint8_t cbor_array_length_size;
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw cbor_array_ptr;
}
cbor_array;

typedef struct cbor_map_entry_s cbor_map_entry;

typedef struct Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry_s
{
  cbor_map_entry *elt;
  size_t len;
}
Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry;

typedef struct cbor_map_s
{
  uint8_t cbor_map_length_size;
  Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry cbor_map_ptr;
}
cbor_map;

typedef struct cbor_int_s
{
  uint8_t cbor_int_type;
  uint8_t cbor_int_size;
  uint64_t cbor_int_value;
}
cbor_int;

#define CBOR_Case_Int 0
#define CBOR_Case_Simple 1
#define CBOR_Case_String 2
#define CBOR_Case_Tagged 3
#define CBOR_Case_Array 4
#define CBOR_Case_Map 5
#define CBOR_Case_Serialized_Tagged 6
#define CBOR_Case_Serialized_Array 7
#define CBOR_Case_Serialized_Map 8

typedef uint8_t cbor_raw_tags;

typedef struct cbor_raw_s
{
  cbor_raw_tags tag;
  union {
    cbor_int case_CBOR_Case_Int;
    uint8_t case_CBOR_Case_Simple;
    cbor_string case_CBOR_Case_String;
    cbor_tagged case_CBOR_Case_Tagged;
    cbor_array case_CBOR_Case_Array;
    cbor_map case_CBOR_Case_Map;
    cbor_serialized case_CBOR_Case_Serialized_Tagged;
    cbor_serialized case_CBOR_Case_Serialized_Array;
    cbor_serialized case_CBOR_Case_Serialized_Map;
  }
  ;
}
cbor_raw;

#define CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Slice 0
#define CBOR_Pulse_Raw_Iterator_CBOR_Raw_Iterator_Serialized 1

typedef uint8_t CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw_tags;

typedef struct CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw_s
{
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw_tags tag;
  union {
    Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw case_CBOR_Raw_Iterator_Slice;
    CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator case_CBOR_Raw_Iterator_Serialized;
  }
  ;
}
CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw;

typedef struct cbor_map_entry_s
{
  cbor_raw cbor_map_entry_key;
  cbor_raw cbor_map_entry_value;
}
cbor_map_entry;

typedef struct CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry_s
{
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw_tags tag;
  union {
    Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry case_CBOR_Raw_Iterator_Slice;
    CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator case_CBOR_Raw_Iterator_Serialized;
  }
  ;
}
CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry;

#define FStar_Pervasives_Native_None 0
#define FStar_Pervasives_Native_Some 1

typedef uint8_t
FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_tags;

typedef struct FStar_Pervasives_Native_option__size_t_s
{
  FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_tags
  tag;
  size_t v;
}
FStar_Pervasives_Native_option__size_t;

typedef struct FStar_Pervasives_Native_option__bool_s
{
  FStar_Pervasives_Native_option__LowParse_Pulse_Base_with_perm_Pulse_Lib_Slice_slice_CBOR_Pulse_Raw_Type_cbor_raw_tags
  tag;
  bool v;
}
FStar_Pervasives_Native_option__bool;

bool
__eq__FStar_Pervasives_Native_option__size_t(
  FStar_Pervasives_Native_option__size_t y,
  FStar_Pervasives_Native_option__size_t x
);

bool
__eq__FStar_Pervasives_Native_option__bool(
  FStar_Pervasives_Native_option__bool y,
  FStar_Pervasives_Native_option__bool x
);

#define CBOR_MAJOR_TYPE_SIMPLE_VALUE (7U)

#define CBOR_MAJOR_TYPE_UINT64 (0U)

#define CBOR_MAJOR_TYPE_NEG_INT64 (1U)

#define CBOR_MAJOR_TYPE_BYTE_STRING (2U)

#define CBOR_MAJOR_TYPE_TEXT_STRING (3U)

#define CBOR_MAJOR_TYPE_ARRAY (4U)

#define CBOR_MAJOR_TYPE_MAP (5U)

#define CBOR_MAJOR_TYPE_TAGGED (6U)

#define MIN_SIMPLE_VALUE_LONG_ARGUMENT (32U)

#define MAX_SIMPLE_VALUE_ADDITIONAL_INFO (23U)

typedef CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
cbor_array_iterator;

typedef CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
cbor_map_iterator;

typedef cbor_raw cbor_nondet_t;

typedef CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
cbor_nondet_array_iterator_t;

typedef CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry
cbor_nondet_map_iterator_t;

typedef cbor_map_entry cbor_nondet_map_entry_t;

bool
cbor_nondet_parse(
  bool check_map_key_bound,
  size_t map_key_bound,
  uint8_t **pinput,
  size_t *plen,
  cbor_raw *dest
);

size_t cbor_nondet_serialize(cbor_raw x, uint8_t *output, size_t len);

uint8_t cbor_nondet_major_type(cbor_raw x);

bool cbor_nondet_read_simple_value(cbor_raw x, uint8_t *dest);

bool cbor_nondet_read_uint64(cbor_raw x, uint64_t *dest);

bool cbor_nondet_read_int64(cbor_raw x, int64_t *dest);

bool cbor_nondet_get_string(cbor_raw x, uint8_t **dest, uint64_t *dlen);

bool cbor_nondet_get_byte_string(cbor_raw x, uint8_t **dest, uint64_t *dlen);

bool cbor_nondet_get_text_string(cbor_raw x, uint8_t **dest, uint64_t *dlen);

bool cbor_nondet_get_tagged(cbor_raw x, cbor_raw *dest, uint64_t *dtag);

bool cbor_nondet_get_array_length(cbor_raw x, uint64_t *dest);

bool
cbor_nondet_array_iterator_start(
  cbor_raw x,
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw *dest
);

bool
cbor_nondet_array_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x
);

uint64_t
cbor_nondet_array_iterator_length(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x
);

bool
cbor_nondet_array_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw *x,
  cbor_raw *dest
);

CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw
cbor_nondet_array_iterator_truncate(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_raw x,
  uint64_t len
);

bool cbor_nondet_get_array_item(cbor_raw x, uint64_t i, cbor_raw *dest);

bool cbor_nondet_get_map_length(cbor_raw x, uint64_t *dest);

bool
cbor_nondet_map_iterator_start(
  cbor_raw x,
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry *dest
);

bool
cbor_nondet_map_iterator_is_empty(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry x
);

cbor_raw cbor_nondet_map_entry_key(cbor_map_entry x);

cbor_raw cbor_nondet_map_entry_value(cbor_map_entry x);

bool
cbor_nondet_map_iterator_next(
  CBOR_Pulse_Raw_Iterator_cbor_raw_iterator__CBOR_Pulse_Raw_Type_cbor_map_entry *x,
  cbor_raw *dest_key,
  cbor_raw *dest_value
);

bool cbor_nondet_equal(cbor_raw x1, cbor_raw x2);

bool cbor_nondet_map_get(cbor_raw x, cbor_raw k, cbor_raw *dest);

bool cbor_nondet_mk_simple_value(uint8_t v, cbor_raw *dest);

cbor_raw cbor_nondet_mk_uint64(uint64_t v);

cbor_raw cbor_nondet_mk_neg_int64(uint64_t v);

cbor_raw cbor_nondet_mk_int64(int64_t v);

bool cbor_nondet_mk_byte_string(uint8_t *a, uint64_t len, cbor_raw *dest);

bool cbor_nondet_mk_text_string(uint8_t *a, uint64_t len, cbor_raw *dest);

bool cbor_nondet_mk_tagged(uint64_t tag, cbor_raw *r, cbor_raw *dest);

bool cbor_nondet_mk_array(cbor_raw *a, uint64_t len, cbor_raw *dest);

cbor_map_entry cbor_nondet_mk_map_entry(cbor_raw xk, cbor_raw xv);

bool cbor_nondet_mk_map(cbor_map_entry *a, uint64_t len, cbor_raw *dest);


#define CBORNondet_H_DEFINED
#endif /* CBORNondet_H */
