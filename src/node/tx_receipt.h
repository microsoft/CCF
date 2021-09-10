// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/history.h"
#include "tls/base64.h"

namespace ccf
{
  struct TxReceipt
  {
    std::vector<uint8_t> signature = {};
    HistoryTree::Hash root = {};
    std::shared_ptr<HistoryTree::Path> path = {};
    NodeId node_id = {};

    TxReceipt(
      const std::vector<uint8_t>& s_,
      const HistoryTree::Hash& r_,
      std::shared_ptr<HistoryTree::Path> p_,
      const NodeId& n_) :
      signature(s_),
      root(r_),
      path(p_),
      node_id(n_)
    {}

    void describe(Receipt& r)
    {
      r.signature = tls::b64_from_raw(signature);
      r.root = root.to_string();
      if (path)
      {
        for (const auto& node : *path)
        {
          Receipt::Element n;
          if (node.direction == HistoryTree::Path::Direction::PATH_LEFT)
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
        r.leaf = r.root;
      }
      r.node_id = node_id;
    }
  };

  using TxReceiptPtr = std::shared_ptr<TxReceipt>;
}