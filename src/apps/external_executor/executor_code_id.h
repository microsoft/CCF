// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/quote_info.h"
#include "ccf/service/code_digest.h"
#include "ccf/service/map.h"
#include "ccf/service/tables/code_id.h"
#include "executor_registration.pb.h"

struct ExecutorNodeInfo
{
  crypto::Pem public_key;
  ccf::Attestation attest;
};

enum class ExecutorCodeStatus
{
  ALLOWED_TO_EXECUTE = 0
};

DECLARE_JSON_ENUM(
  ExecutorCodeStatus,
  {{ExecutorCodeStatus::ALLOWED_TO_EXECUTE, "AllowedToExecute"}});

struct GetExecutorCode
{
  struct Version
  {
    std::string digest;
    ExecutorCodeStatus status;
    std::optional<ccf::QuoteFormat> platform;
  };

  struct Out
  {
    std::vector<GetExecutorCode::Version> versions = {};
  };
};

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetExecutorCode::Version)
DECLARE_JSON_REQUIRED_FIELDS(GetExecutorCode::Version, digest, status)
DECLARE_JSON_OPTIONAL_FIELDS(GetExecutorCode::Version, platform)
DECLARE_JSON_TYPE(GetExecutorCode::Out)
DECLARE_JSON_REQUIRED_FIELDS(GetExecutorCode::Out, versions)

struct ExecutorCodeInfo
{
  ExecutorCodeStatus status;
  ccf::QuoteFormat platform;
};

DECLARE_JSON_TYPE(ExecutorCodeInfo);
DECLARE_JSON_REQUIRED_FIELDS(ExecutorCodeInfo, status, platform);

using ExecutorCodeIDs = ccf::ServiceMap<ccf::CodeDigest, ExecutorCodeInfo>;

static constexpr auto EXECUTOR_CODE_IDS =
  "public:ccf.gov.nodes.executor_code_ids";