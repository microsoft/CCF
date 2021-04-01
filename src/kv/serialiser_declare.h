// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace kv
{
  // This awkward forward declaration allows the <K,V>-templated serialisers to
  // depend on kv_types.h, and removes the reverse dependency. Once these
  // serialisers work purely with pre-serialised byte-vectors, we can create
  // replace this with an AbstractTxSerialiser pattern.
  template <typename W>
  class GenericSerialiseWrapper;

  template <typename W>
  class GenericDeserialiseWrapper;

#ifdef USE_NLJSON_KV_SERIALISER
  class JsonWriter;
  using KvStoreSerialiser = GenericSerialiseWrapper<JsonWriter>;

  class JsonReader;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<JsonReader>;
#else
  class RawWriter;
  using KvStoreSerialiser = GenericSerialiseWrapper<RawWriter>;

  class RawReader;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<RawReader>;
#endif
}
