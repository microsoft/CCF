

#ifndef CBORNondet_H
#define CBORNondet_H

#include "krmllib.h"

#include "CBORNondetType.h"

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

bool
cbor_nondet_parse(
  bool check_map_key_bound,
  size_t map_key_bound,
  uint8_t **pinput,
  size_t *plen,
  cbor_raw *dest
);

size_t cbor_nondet_size(cbor_raw x, size_t bound);

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

bool cbor_nondet_array_iterator_start(cbor_raw x, cbor_array_iterator *dest);

bool cbor_nondet_array_iterator_is_empty(cbor_array_iterator x);

uint64_t cbor_nondet_array_iterator_length(cbor_array_iterator x);

bool cbor_nondet_array_iterator_next(cbor_array_iterator *x, cbor_raw *dest);

cbor_array_iterator cbor_nondet_array_iterator_truncate(cbor_array_iterator x, uint64_t len);

bool cbor_nondet_get_array_item(cbor_raw x, uint64_t i, cbor_raw *dest);

bool cbor_nondet_get_map_length(cbor_raw x, uint64_t *dest);

bool cbor_nondet_map_iterator_start(cbor_raw x, cbor_map_iterator *dest);

bool cbor_nondet_map_iterator_is_empty(cbor_map_iterator x);

cbor_raw cbor_nondet_map_entry_key(cbor_map_entry x);

cbor_raw cbor_nondet_map_entry_value(cbor_map_entry x);

bool
cbor_nondet_map_iterator_next(cbor_map_iterator *x, cbor_raw *dest_key, cbor_raw *dest_value);

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

typedef struct cbor_nondet_map_get_multiple_entry_t_s
{
  cbor_raw key;
  cbor_raw value;
  bool found;
}
cbor_nondet_map_get_multiple_entry_t;

bool
cbor_nondet_map_get_multiple(
  cbor_raw map,
  cbor_nondet_map_get_multiple_entry_t *dest,
  size_t len
);


#define CBORNondet_H_DEFINED
#endif /* CBORNondet_H */
