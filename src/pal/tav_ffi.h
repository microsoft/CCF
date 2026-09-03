// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "tav/snp.h"
#include "tav/utils.h"

#include <memory>

namespace ccf::pal
{
  template <typename T, void (*Free)(T*)>
  struct TavDeleter
  {
    void operator()(T* ptr) const noexcept
    {
      Free(ptr);
    }
  };

  template <typename T, void (*Free)(T*)>
  using TavUniquePtr = std::unique_ptr<T, TavDeleter<T, Free>>;

  using TavErrorPtr = TavUniquePtr<TavError, tav_error_free>;
  using TavAttestationReportPtr =
    TavUniquePtr<TavSnpAttestationReport, tav_snp_attestation_report_free>;
}
