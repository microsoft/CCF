// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/base64.h"
#include "node/history.h"

namespace ccf
{
  struct TxReceipt
  {
    std::vector<uint8_t> signature = {};
    HistoryTree::Hash root = {};
    std::shared_ptr<ccf::HistoryTree::Path> path = {};
    ccf::NodeId node_id = {};
    std::optional<crypto::Pem> cert = std::nullopt;

    TxReceipt(
      const std::vector<uint8_t>& s_,
      const HistoryTree::Hash& r_,
      std::shared_ptr<ccf::HistoryTree::Path> p_,
      const NodeId& n_,
      const std::optional<crypto::Pem>& c_) :
      signature(s_),
      root(r_),
      path(p_),
      node_id(n_),
      cert(c_)
    {}

    void describe(ccf::Receipt& r, bool include_root = false)
    {
      r.signature = crypto::b64_from_raw(signature);
      if (include_root)
      {
        r.root = root.to_string();
      }
      if (path)
      {
        for (const auto& node : *path)
        {
          ccf::Receipt::Element n;
          if (node.direction == ccf::HistoryTree::Path::Direction::PATH_LEFT)
          {
            n.left = node.hash.to_string();
          }
          else
          {
            n.right = node.hash.to_string();
          }
          r.proof.emplace_back(std::move(n));
        }
        r.leaf = path->leaf().to_string();
      }
      else
      {
        r.leaf = root.to_string();
      }
      r.node_id = node_id;

      if (cert.has_value())
      {
        r.cert = cert->str();
      }
    }
  };

  using TxReceiptPtr = std::shared_ptr<TxReceipt>;
}
