// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/context.h"
#include "ccf/js/extensions/ccf/converters.h"
#include "ccf/js/extensions/ccf/crypto.h"
#include "ccf/js/extensions/ccf/gov.h"
#include "ccf/js/extensions/ccf/kv.h"
#include "ccf/js/extensions/console.h"
#include "ccf/js/extensions/math/random.h"
#include "ccf/js/extensions/snp_attestation.h"

namespace ccf::js
{
  // This is intended to extend a js::core::Context with various CCF-specific
  // extensions, expected to be accessible in every execution context (eg -
  // ccf.bufToStr converters, ccf.crypto helpers). This is
  // implemented as a CRTP mixin so that you could build your own hierarchy.
  template <typename Base>
  class WithCommonExtensions : public Base
  {
  public:
    WithCommonExtensions(TxAccess acc) : Base(acc)
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

      // add snp_attestation.*
      Base::add_extension(
        std::make_shared<ccf::js::extensions::SnpAttestationExtension>());

      // add ccf.gov.*
      Base::add_extension(
        std::make_shared<ccf::js::extensions::GovExtension>());
    }
  };

  template <typename Base>
  class WithKVExtension : public Base
  {
  public:
    WithKVExtension(TxAccess acc, ccf::kv::Tx* tx) : Base(acc)
    {
      // add ccf.kv.*
      Base::add_extension(
        std::make_shared<ccf::js::extensions::KvExtension>(tx));
    }

    ccf::js::core::JSWrappedValue inner_call(
      const ccf::js::core::JSWrappedValue& f,
      const std::vector<ccf::js::core::JSWrappedValue>& argv) override
    {
      auto ret = Base::inner_call(f, argv);
      auto* extension =
        Base::template get_extension<ccf::js::extensions::KvExtension>();
      if (extension != nullptr)
      {
        extension->rethrow_trapped_exceptions();
      }

      return ret;
    }
  };

  using CommonContext = WithCommonExtensions<js::core::Context>;
  using CommonContextWithLocalTx = WithKVExtension<CommonContext>;
}
