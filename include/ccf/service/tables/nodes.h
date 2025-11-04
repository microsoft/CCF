// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/crypto/verifier.h"
#include "ccf/entity_id.h"
#include "ccf/kv/map.h"
#include "ccf/service/blit_serialiser_pem.h"
#include "ccf/service/map.h"
#include "ccf/service/node_info.h"

#include <string>
#include <vector>

namespace ccf
{
  using Nodes = ServiceMap<NodeId, NodeInfo>;
  using NodeEndorsedCertificates =
    ccf::kv::RawCopySerialisedMap<NodeId, ccf::crypto::Pem>;

  namespace Tables
  {
    static constexpr auto NODES = "public:ccf.gov.nodes.info";
    static constexpr auto NODE_ENDORSED_CERTIFICATES =
      "public:ccf.gov.nodes.endorsed_certificates";
  }

  inline NodeId compute_node_id_from_pubk_der(
    const std::vector<uint8_t>& node_pubk_der)
  {
    return ccf::crypto::Sha256Hash(node_pubk_der).hex_str();
  }

  inline NodeId compute_node_id_from_cert_der(
    const std::vector<uint8_t>& node_cert_der)
  {
    return compute_node_id_from_pubk_der(
      ccf::crypto::public_key_der_from_cert(node_cert_der));
  }

  inline NodeId compute_node_id_from_kp(
    const ccf::crypto::ECKeyPairPtr& node_sign_kp)
  {
    return compute_node_id_from_pubk_der(node_sign_kp->public_key_der());
  }
}
