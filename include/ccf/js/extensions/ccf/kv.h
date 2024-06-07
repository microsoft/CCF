// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"
#include "ccf/js/namespace_restrictions.h"

#include <memory>

namespace kv
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

    ccf::js::NamespaceRestrictions restrictions;

    KvExtension(kv::Tx* t, const ccf::js::NamespaceRestrictions& nr = {});
    ~KvExtension();

    void install(js::core::Context& ctx);
  };
}