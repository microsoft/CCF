// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/core/context.h"
#include "js/extensions/ccf/converters.h"
#include "js/extensions/ccf/crypto.h"
#include "js/extensions/ccf/kv.h"
#include "js/extensions/console.h"
#include "js/extensions/math/random.h"

namespace ccf::js
{
  // This is intended to extend a js::core::Context with various CCF-specific
  // extensions, expected to be accessible in every execution context (eg -
  // ccf.bufToStr converters, ccf.crypto helpers, kv access). This is
  // implemented as a CRTP mixin so that you could build your own hierarchy.
  template <typename Base>
  class WithCommonExtensions : public Base
  {
  public:
    WithCommonExtensions(TxAccess acc, kv::Tx* tx) : Base(acc)
    {
      // override Math.random
      Base::add_extension(
        std::make_shared<ccf::js::extensions::MathRandomExtension>());

      // add console.[debug|log|...]
      Base::add_extension(
        std::make_shared<ccf::js::extensions::ConsoleExtension>());

      // add ccf.[strToBuf|bufToStr|...]
      Base::add_extension(
        std::make_shared<ccf::js::extensions::ConvertersExtension>());

      // add ccf.crypto.*
      Base::add_extension(
        std::make_shared<ccf::js::extensions::CryptoExtension>());

      // add kv.*
      Base::add_extension(
        std::make_shared<ccf::js::extensions::KvExtension>(tx));
    }
  };

  using CommonContext = WithCommonExtensions<js::core::Context>;
}
