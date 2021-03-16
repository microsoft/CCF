// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "node/whitelists.h"

#include <map>

namespace ccf
{
  static const std::map<WlIds, Whitelist> default_whitelists = {
    {MEMBER_CAN_READ,
     {Tables::MEMBERS,
      Tables::MEMBER_ACKS,
      Tables::USER_CERTS,
      Tables::USER_DATA,
      Tables::NODES,
      Tables::VALUES,
      Tables::SIGNATURES,
      Tables::NODE_CODE_IDS,
      Tables::WHITELISTS,
      Tables::PROPOSALS,
      Tables::GOV_SCRIPTS,
      Tables::APP_SCRIPTS,
      Tables::MODULES,
      Tables::SERVICE,
      Tables::CONFIGURATION,
      Tables::CA_CERT_BUNDLE_PEMS,
      Tables::SERVICE_PRINCIPALS,
      Tables::JWT_ISSUERS,
      Tables::JWT_PUBLIC_SIGNING_KEYS,
      Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER}},

    {MEMBER_CAN_PROPOSE,
     {Tables::USER_CERTS,
      Tables::USER_DATA,
      Tables::VALUES,
      Tables::WHITELISTS,
      Tables::GOV_SCRIPTS,
      Tables::APP_SCRIPTS,
      Tables::MODULES,
      Tables::CONFIGURATION,
      Tables::CA_CERT_BUNDLE_PEMS,
      Tables::SERVICE_PRINCIPALS,
      Tables::JWT_ISSUERS,
      Tables::JWT_PUBLIC_SIGNING_KEYS,
      Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER}}};
}