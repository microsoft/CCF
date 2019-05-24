// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/hash.h"
#include "enclave/oe_shim.h"
#include "frontend.h"
#include "node/entities.h"

namespace ccf
{
  class NodesCallRpcFrontend : public RpcFrontend
  {
  public:
    NodesCallRpcFrontend(
      Store& tables, AbstractNodeState& node, NetworkState& network) :
      RpcFrontend(tables, nullptr, tables.get<Certs>(Tables::NODE_CERTS))
    {
      auto accept = [&node, &network](RequestArgs& args) {
        // Retrieve joining node's cert and quote
        auto nodes_view = args.tx.get_view(network.nodes);
        auto joining_nodeinfo = nodes_view->get(args.caller_id).value();

#ifdef GET_QUOTE
        // Parse quote and verify quote data
        oe_report_t parsed_quote = {0};
        oe_result_t result = oe_verify_report(
          joining_nodeinfo.quote.data(),
          joining_nodeinfo.quote.size(),
          &parsed_quote);

        if (result != OE_OK)
        {
          LOG_FAIL << "Quote could not be verified " << oe_result_str(result)
                   << std::endl;
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INTERNAL_ERROR, "Quote could not be verified");
        }

        // Verify enclave measurement
        auto codeid_view = args.tx.get_view(network.code_id);
        CodeStatus code_id_status = CodeStatus::UNKNOWN;

        codeid_view->foreach([&parsed_quote, &code_id_status](
                               const CodeVersion& cv, const CodeInfo& ci) {
          if (
            memcmp(
              ci.digest.data(),
              parsed_quote.identity.unique_id,
              CODE_DIGEST_BYTES) == 0)
          {
            code_id_status = ci.status;
          }
        });

        if (code_id_status != CodeStatus::ACCEPTED)
        {
          return jsonrpc::error(
            (code_id_status == CodeStatus::RETIRED ?
               jsonrpc::ErrorCodes::CODE_ID_RETIRED :
               jsonrpc::ErrorCodes::CODE_ID_NOT_FOUND),
            "Quote does not contain known enclave measurement");
        }

        // Verify quote data
        crypto::Sha256Hash hash{joining_nodeinfo.cert};
        if (
          parsed_quote.report_data_size != crypto::Sha256Hash::SIZE &&
          memcmp(hash.h, parsed_quote.report_data, crypto::Sha256Hash::SIZE) !=
            0)
        {
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INTERNAL_ERROR,
            "Quote does not contain joining node certificate hash");
        }
#else
        LOG_INFO << "Skipped joining node quote verification." << std::endl;
#endif

        // TODO(#important,#TR): In addition to verifying the quote, we should
        // go through a round of governance before marking the node as TRUSTED
        // (section IV-D).
        joining_nodeinfo.status = NodeStatus::TRUSTED;
        nodes_view->put(args.caller_id, joining_nodeinfo);

        LOG_INFO << "Accepting a new node to the network as node "
                 << args.caller_id << std::endl;

        // Set joiner's fresh key for encrypting past network secrets
        node.set_joiner_key(args.caller_id, args.params["raw_fresh_key"]);

        // Send network secrets and NodeID
        return jsonrpc::success(nlohmann::json(
          JoinNetworkNodeToNode::Out{args.caller_id,
                                     network.secrets->get_current(),
                                     network.secrets->get_current_version()}));
      };

      install(NodeProcs::JOIN, accept, Write);
    }
  };
}
