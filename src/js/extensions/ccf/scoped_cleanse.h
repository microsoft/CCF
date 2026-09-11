// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/crypto.h>

namespace ccf::js
{
  // RAII guard that securely erases the bytes of a container-like target on
  // destruction, so that private key material and other secrets are scrubbed
  // from memory on every exit path (normal return, early return, or exception
  // unwind). The referenced target must outlive the guard.
  //
  // T must expose non-const data(), size() and empty() member functions, and
  // the pointer returned by data() must be convertible to void*. This covers
  // std::string, std::vector<uint8_t> and ccf::crypto::Pem.
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
      if (target != nullptr && !target->empty())
      {
        OPENSSL_cleanse(target->data(), target->size());
      }
    }

  private:
    T* target;
  };
}
