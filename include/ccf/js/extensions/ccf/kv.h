// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"
#include "ccf/js/namespace_restrictions.h"

#include <memory>

namespace ccf::kv
{
  class Tx;
}

namespace ccf::js::extensions
{
  /**
   * Adds ccf.kv object, containing an index[] operator to return views over
   * single maps.
   *
   **/
  class KvExtension : public ExtensionInterface
  {
  public:
    struct Impl;

    std::unique_ptr<Impl> impl;

    ccf::js::NamespaceRestriction namespace_restriction;

    KvExtension(ccf::kv::Tx* t, ccf::js::NamespaceRestriction nr = {});
    ~KvExtension() override;

    void install(js::core::Context& ctx) override;

    void rethrow_trapped_exceptions() const;
  };
}