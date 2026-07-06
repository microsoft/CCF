

#ifndef internal_CBORNondet_H
#define internal_CBORNondet_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "krmllib.h"

#include "CBORNondetType.h"
#include "../CBORNondet.h"

#define FStar_Pervasives_Native_None 0
#define FStar_Pervasives_Native_Some 1

typedef uint8_t FStar_Pervasives_Native_option__bool_tags;

typedef struct FStar_Pervasives_Native_option__bool_s
{
  FStar_Pervasives_Native_option__bool_tags tag;
  bool v;
}
FStar_Pervasives_Native_option__bool;

typedef struct FStar_Pervasives_Native_option__size_t_s
{
  FStar_Pervasives_Native_option__bool_tags tag;
  size_t v;
}
FStar_Pervasives_Native_option__size_t;

size_t
CBOR_Pulse_Raw_Format_Serialize_ser_(
  cbor_raw x_,
  CBOR_Pulse_Raw_Slice_byte_slice out,
  size_t offset
);

bool CBOR_Pulse_Raw_Format_Serialize_siz_(cbor_raw x_, size_t *out);

bool
CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth_aux(
  size_t bound,
  CBOR_Pulse_Raw_Slice_byte_slice *pl,
  size_t n1
);

FStar_Pervasives_Native_option__bool
CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_map_hd_basic(
  FStar_Pervasives_Native_option__size_t map_bound,
  CBOR_Pulse_Raw_Slice_byte_slice l1,
  CBOR_Pulse_Raw_Slice_byte_slice l2
);

bool CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(cbor_raw x1, cbor_raw x2);

#if defined(__cplusplus)
}
#endif

#define internal_CBORNondet_H_DEFINED
#endif /* internal_CBORNondet_H */
