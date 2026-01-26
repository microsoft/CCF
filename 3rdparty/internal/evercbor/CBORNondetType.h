

#ifndef CBORNondetType_H
#define CBORNondetType_H

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

typedef struct cbor_serialized_s
{
  CBOR_Spec_Raw_Base_raw_uint64 cbor_serialized_header;
  Pulse_Lib_Slice_slice__uint8_t cbor_serialized_payload;
}
cbor_serialized;

typedef struct cbor_int_s
{
  uint8_t cbor_int_type;
  uint8_t cbor_int_size;
  uint64_t cbor_int_value;
}
cbor_int;

typedef struct cbor_string_s
{
  uint8_t cbor_string_type;
  uint8_t cbor_string_size;
  Pulse_Lib_Slice_slice__uint8_t cbor_string_ptr;
}
cbor_string;

typedef struct cbor_raw_s cbor_raw;

typedef struct cbor_raw_s cbor_raw;

typedef struct cbor_tagged_s
{
  CBOR_Spec_Raw_Base_raw_uint64 cbor_tagged_tag;
  cbor_raw *cbor_tagged_ptr;
}
cbor_tagged;

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

typedef struct cbor_map_entry_s
{
  cbor_raw cbor_map_entry_key;
  cbor_raw cbor_map_entry_value;
}
cbor_map_entry;

#define CBOR_Raw_Iterator_Slice 0
#define CBOR_Raw_Iterator_Serialized 1

typedef uint8_t cbor_array_iterator_tags;

typedef struct cbor_array_iterator_s
{
  cbor_array_iterator_tags tag;
  union {
    Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_raw case_CBOR_Raw_Iterator_Slice;
    CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator case_CBOR_Raw_Iterator_Serialized;
  }
  ;
}
cbor_array_iterator;

typedef struct cbor_map_iterator_s
{
  cbor_array_iterator_tags tag;
  union {
    Pulse_Lib_Slice_slice__CBOR_Pulse_Raw_Type_cbor_map_entry case_CBOR_Raw_Iterator_Slice;
    CBOR_Pulse_Raw_Iterator_Base_cbor_raw_serialized_iterator case_CBOR_Raw_Iterator_Serialized;
  }
  ;
}
cbor_map_iterator;

typedef cbor_raw cbor_nondet_t;

typedef cbor_array_iterator cbor_nondet_array_iterator_t;

typedef cbor_map_iterator cbor_nondet_map_iterator_t;

typedef cbor_map_entry cbor_nondet_map_entry_t;


#define CBORNondetType_H_DEFINED
#endif /* CBORNondetType_H */
