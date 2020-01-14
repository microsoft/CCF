// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "node/rpc/jsonrpc.h"

#include <nlohmann/json.hpp>

using NodeId = uint64_t;

struct PrincipalInfo
{
  NodeId id;
  short port;
  std::string ip;
  std::vector<uint8_t> cert;
  std::string host_name;
  bool is_replica;
};

DECLARE_JSON_TYPE(PrincipalInfo);
DECLARE_JSON_REQUIRED_FIELDS(
  PrincipalInfo, id, port, ip, cert, host_name, is_replica);

struct GeneralInfo
{
  int num_replicas;
  int num_clients;
  int max_faulty;
  std::string service_name;
  int auth_timeout;
  long view_timeout;
  long status_timeout;
  long recovery_timeout;
  uint64_t max_requests_between_signatures;
  std::vector<PrincipalInfo> principal_info;
};

DECLARE_JSON_TYPE(GeneralInfo);
DECLARE_JSON_REQUIRED_FIELDS(
  GeneralInfo,
  num_replicas,
  num_clients,
  max_faulty,
  service_name,
  auth_timeout,
  view_timeout,
  status_timeout,
  recovery_timeout,
  max_requests_between_signatures,
  principal_info);

struct PrivateKey
{
  std::string privk;
};

DECLARE_JSON_TYPE(PrivateKey);
DECLARE_JSON_REQUIRED_FIELDS(PrivateKey, privk);

struct NodeInfo
{
  // personal info
  PrincipalInfo own_info;
  std::string privk;
  GeneralInfo general_info;
};
