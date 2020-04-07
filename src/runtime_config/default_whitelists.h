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
      Tables::MEMBER_CERTS,
      Tables::MEMBER_ACKS,
      Tables::USERS,
      Tables::USER_CERTS,
      Tables::NODES,
      Tables::VALUES,
      Tables::SIGNATURES,
      Tables::USER_CLIENT_SIGNATURES,
      Tables::MEMBER_CLIENT_SIGNATURES,
      Tables::NODE_CODE_IDS,
      Tables::USER_CODE_IDS,
      Tables::WHITELISTS,
      Tables::PROPOSALS,
      Tables::GOV_SCRIPTS,
      Tables::APP_SCRIPTS,
      Tables::SERVICE,
      Tables::CONFIGURATION}},

    {MEMBER_CAN_PROPOSE,
     {Tables::USERS,
      Tables::USER_CERTS,
      Tables::VALUES,
      Tables::WHITELISTS,
      Tables::GOV_SCRIPTS,
      Tables::APP_SCRIPTS,
      Tables::CONFIGURATION}},

    {USER_APP_CAN_READ_ONLY,
     {Tables::MEMBERS,
      Tables::MEMBER_CERTS,
      Tables::MEMBER_ACKS,
      Tables::USERS,
      Tables::WHITELISTS,
      Tables::GOV_SCRIPTS,
      Tables::APP_SCRIPTS,
      Tables::GOV_HISTORY}}};
}