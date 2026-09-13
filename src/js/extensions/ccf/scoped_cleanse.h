// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/jwk.h"

#include <openssl/crypto.h>

namespace ccf::js
{
  namespace detail
  {
    template <typename T>
      requires requires(T& target) {
        target.data();
        target.size();
        target.empty();
      }
    void cleanse(T& target)
    {
      if (!target.empty())
      {
        OPENSSL_cleanse(target.data(), target.size());
      }
    }

    inline void cleanse(ccf::crypto::JsonWebKeyECPublic& jwk) {}
    inline void cleanse(ccf::crypto::JsonWebKeyRSAPublic& jwk) {}
    inline void cleanse(ccf::crypto::JsonWebKeyEdDSAPublic& jwk) {}

    inline void cleanse(ccf::crypto::JsonWebKeyECPrivate& jwk)
    {
      cleanse(jwk.d);
    }

    inline void cleanse(ccf::crypto::JsonWebKeyRSAPrivate& jwk)
    {
      cleanse(jwk.d);
      cleanse(jwk.p);
      cleanse(jwk.q);
      cleanse(jwk.dp);
      cleanse(jwk.dq);
      cleanse(jwk.qi);
    }

    inline void cleanse(ccf::crypto::JsonWebKeyEdDSAPrivate& jwk)
    {
      cleanse(jwk.d);
    }

    inline void cleanse(nlohmann::json& value)
    {
      if (auto* string = value.get_ptr<nlohmann::json::string_t*>())
      {
        cleanse(*string);
      }
      else if (auto* array = value.get_ptr<nlohmann::json::array_t*>())
      {
        for (auto& child : *array)
        {
          cleanse(child);
        }
      }
      else if (auto* object = value.get_ptr<nlohmann::json::object_t*>())
      {
        for (auto& [key, child] : *object)
        {
          cleanse(child);
        }
      }
    }
  }

  // Scrubs owned byte containers, private JWK fields and JSON string values
  // on scope exit. The target must outlive the guard and must not discard
  // secret storage (for example by shrinking or overwriting it) while guarded.
  template <typename T>
  class ScopedCleanse
  {
  public:
    explicit ScopedCleanse(T& target) : target(&target) {}

    ScopedCleanse(const ScopedCleanse&) = delete;
    ScopedCleanse& operator=(const ScopedCleanse&) = delete;
    ScopedCleanse(ScopedCleanse&&) = delete;
    ScopedCleanse& operator=(ScopedCleanse&&) = delete;

    ~ScopedCleanse()
    {
      detail::cleanse(*target);
    }

  private:
    T* target;
  };
}
