/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

/* Note: including some forward-references because Prims.strcat is meant to go
 * away in favor of FStar.String.strcat (will it ever happen?). */

#include "Prims.h"
#include "FStar_String.h"
#include "FStar_Int32.h"

Prims_string Prims_string_of_int(krml_checked_int_t i) {
  return FStar_Int32_to_string(i);
}

Prims_string Prims_strcat(Prims_string s0, Prims_string s1) {
  return FStar_String_strcat(s0, s1);
}

bool __eq__Prims_string(Prims_string s1, Prims_string s2) {
  return (strcmp(s1, s2) == 0);
}

inline Prims_string Prims_string_of_bool(bool b) {
  if (b) {
    return "true";
  } else {
    return "false";
  }
}

bool Prims_op_GreaterThanOrEqual(int32_t x, int32_t y) {
  return x >= y;
}

bool Prims_op_LessThanOrEqual(int32_t x, int32_t y) {
  return x <= y;
}

bool Prims_op_GreaterThan(int32_t x, int32_t y) {
  return x > y;
}

bool Prims_op_LessThan(int32_t x, int32_t y) {
  return x < y;
}

int32_t Prims_pow2(int32_t x) {
  /* FIXME incorrect bounds check here */
  RETURN_OR((int64_t)1 << (int64_t)x);
}

int32_t Prims_op_Multiply(int32_t x, int32_t y) {
  RETURN_OR((int64_t)x * (int64_t)y);
}

int32_t Prims_op_Addition(int32_t x, int32_t y) {
  RETURN_OR((int64_t)x + (int64_t)y);
}

int32_t Prims_op_Subtraction(int32_t x, int32_t y) {
  RETURN_OR((int64_t)x - (int64_t)y);
}

int32_t Prims_op_Division(int32_t x, int32_t y) {
  RETURN_OR((int64_t)x / (int64_t)y);
}

int32_t Prims_op_Modulus(int32_t x, int32_t y) {
  RETURN_OR((int64_t)x % (int64_t)y);
}
