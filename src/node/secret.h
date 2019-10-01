// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <vector>

namespace ccf
{
  // Individual secret made of cert, priv_key and master that is valid for a
  // specific version range
  struct Secret
  {
    std::vector<uint8_t> cert;
    std::vector<uint8_t> priv_key;
    std::vector<uint8_t> master;

    bool operator==(const Secret& other) const
    {
      return cert == other.cert && priv_key == other.priv_key &&
        master == other.master;
    }

    Secret(
      std::vector<uint8_t> cert_ = {},
      std::vector<uint8_t> priv_key_ = {},
      std::vector<uint8_t> master_ = {}) :
      cert(cert_),
      priv_key(priv_key_),
      master(master_)
    {}

    // TODO(#refactoring): Use msgpack for serialisation
    std::vector<uint8_t> serialise()
    {
      std::vector<uint8_t> serialised_secret;

      auto space =
        3 * sizeof(size_t) + cert.size() + priv_key.size() + master.size();
      serialised_secret.resize(space);
      auto data_ = serialised_secret.data();

      serialized::write(data_, space, cert.size());
      serialized::write(data_, space, cert.data(), cert.size());
      serialized::write(data_, space, priv_key.size());
      serialized::write(data_, space, priv_key.data(), priv_key.size());
      serialized::write(data_, space, master.size());
      serialized::write(data_, space, master.data(), master.size());

      return std::move(serialised_secret);
    }

    void deserialise(const std::vector<uint8_t>& serialised_secret)
    {
      auto data_ = static_cast<const uint8_t*>(serialised_secret.data());
      auto size = serialised_secret.size();

      auto cert_len = serialized::read<size_t>(data_, size);
      cert = serialized::read(data_, size, cert_len);
      auto priv_key_len = serialized::read<size_t>(data_, size);
      priv_key = serialized::read(data_, size, priv_key_len);
      auto master_len = serialized::read<size_t>(data_, size);
      master = serialized::read(data_, size, master_len);
    }
  };
}