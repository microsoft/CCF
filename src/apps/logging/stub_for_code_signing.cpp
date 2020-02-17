// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// This is a hack to avoid recompiling liblogging.enclave.so:
// A binary that exposes the same API as the current one, yet produces
// a different signature, is needed so that code upgrade can be tested.
// The quick way to do that is to copy the binary and modify a few
// bytes on the text section of the new binary. This function produces
// a few bytes that can be safely overwritten.
extern "C" __attribute__((visibility("default"))) int stub_for_code_signing()
{
  return -1;
}
