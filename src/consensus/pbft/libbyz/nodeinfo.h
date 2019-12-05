// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include <nlohmann/json.hpp>

using NodeId = uint64_t;

struct PrincipalInfo
{
  NodeId id;
  short port;
  std::string ip;
  std::string pubk_sig;
  std::string pubk_enc;
  std::string host_name;
  bool is_replica;
};

inline void from_json(const nlohmann::json& j, PrincipalInfo& pi)
{
  pi.id = j["id"];
  pi.port = j["port"];
  pi.ip = j["ip"];
  pi.pubk_sig = j["pubk_sig"];
  pi.pubk_enc = j["pubk_enc"];
  pi.host_name = j["host_name"];
  pi.is_replica = j["is_replica"];
}

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

inline void from_json(const nlohmann::json& j, GeneralInfo& gi)
{
  gi.num_replicas = j["num_replicas"];
  gi.num_clients = j["num_clients"];
  gi.max_faulty = j["max_faulty"];
  gi.service_name = j["service_name"];
  gi.auth_timeout = j["auth_timeout"];
  gi.view_timeout = j["view_timeout"];
  gi.status_timeout = j["status_timeout"];
  gi.recovery_timeout = j["recovery_timeout"];
  gi.max_requests_between_signatures = j["max_requests_between_signatures"];
  std::vector<PrincipalInfo> temp = j["principal_info"];
  gi.principal_info = std::move(temp);
}

struct NodeInfo
{
  // personal info
  PrincipalInfo own_info;
  std::string privk;
  GeneralInfo general_info;
};
