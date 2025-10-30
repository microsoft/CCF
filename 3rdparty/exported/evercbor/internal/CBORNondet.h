

#ifndef internal_CBORNondet_H
#define internal_CBORNondet_H

#include "krmllib.h"

#include "../CBORNondet.h"

size_t
CBOR_Pulse_Raw_Format_Serialize_ser_(
  cbor_raw x_,
  Pulse_Lib_Slice_slice__uint8_t out,
  size_t offset
);

bool CBOR_Pulse_Raw_Format_Serialize_siz_(cbor_raw x_, size_t *out);

bool
CBOR_Pulse_Raw_EverParse_Nondet_Gen_impl_check_map_depth_aux(
  size_t bound,
  Pulse_Lib_Slice_slice__uint8_t *pl,
  size_t n1
);

FStar_Pervasives_Native_option__bool
CBOR_Pulse_Raw_EverParse_Nondet_Basic_impl_check_equiv_map_hd_basic(
  FStar_Pervasives_Native_option__size_t map_bound,
  Pulse_Lib_Slice_slice__uint8_t l1,
  Pulse_Lib_Slice_slice__uint8_t l2
);

bool CBOR_Pulse_Raw_Nondet_Compare_cbor_nondet_equiv(cbor_raw x1, cbor_raw x2);


#define internal_CBORNondet_H_DEFINED
#endif /* internal_CBORNondet_H */
