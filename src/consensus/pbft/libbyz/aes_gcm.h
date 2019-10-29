// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

  typedef struct aes_gcm_ctx* aes_gcm_ctx_t;

  aes_gcm_ctx_t aes_gcm_new(char key[]);
  /* Dynamically allocate a aes_gcm_ctx struct, initialize variables,
   * generate subkeys from key.
   */

  int aes_gcm_delete(aes_gcm_ctx_t ctx);
  /* Deallocate the context structure */

  int aes_gcm(
    aes_gcm_ctx_t ctx, char* input, long len, char tag[], char nonce[8]);
  /* All-in-one implementation of the functions Reset, Update and Final */

#ifdef __cplusplus
}
#endif
