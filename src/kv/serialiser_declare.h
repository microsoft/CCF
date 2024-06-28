// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf::kv
{
  // This awkward forward declaration allows the <K,V>-templated serialisers to
  // depend on kv_types.h, and removes the reverse dependency. Once these
  // serialisers work purely with pre-serialised byte-vectors, we can create
  // replace this with an AbstractTxSerialiser pattern.
  template <typename W>
  class GenericSerialiseWrapper;

  template <typename W>
  class GenericDeserialiseWrapper;

  class RawWriter;
  using KvStoreSerialiser = GenericSerialiseWrapper<RawWriter>;

  class RawReader;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<RawReader>;
}
