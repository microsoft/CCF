// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Pure chain-shape predicates used by NetworkIdentitySubsystem. Kept in
// a small header so the unit test target can link against them without
// pulling in the heavyweight subsystem dependencies.

#include "ccf/network_identity_interface.h"
#include "ccf/tx_id.h"
#include "consensus/aft/raft_types.h"
#include "service/tables/previous_service_identity.h"

#include <fmt/format.h>
#include <stdexcept>

namespace ccf
{
  inline bool is_self_endorsement(const ccf::CoseEndorsement& endorsement)
  {
    return !endorsement.previous_version.has_value();
  }

  inline bool is_ill_formed(const ccf::CoseEndorsement& endorsement)
  {
    return endorsement.endorsement_epoch_end.has_value() &&
      endorsement.endorsement_epoch_end->seqno <
      endorsement.endorsement_epoch_begin.seqno;
  }

  inline void verify_endorsements_connected(
    const ccf::CoseEndorsement& newer, const ccf::CoseEndorsement& older)
  {
    if (!older.endorsement_epoch_end.has_value())
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "from {} does not have an epoch end",
        older.endorsement_epoch_begin.to_str()));
    }

    if (
      newer.endorsement_epoch_begin.view - aft::starting_view_change !=
        older.endorsement_epoch_end->view ||
      newer.endorsement_epoch_begin.seqno - 1 !=
        older.endorsement_epoch_end->seqno)
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "epoch end {} is not chained with newer endorsement epoch begin {}",
        older.endorsement_epoch_end->to_str(),
        newer.endorsement_epoch_begin.to_str()));
    }
  }

  // Verify the newest endorsement immediately precedes the current service.
  inline void validate_chain_front_connection(
    const ccf::CoseEndorsement& newest, const ccf::TxID& current_service_from)
  {
    if (!newest.endorsement_epoch_end.has_value())
    {
      throw std::logic_error(fmt::format(
        "The last fetched endorsement at {} has no epoch end",
        newest.endorsement_epoch_begin.seqno));
    }
    if (
      current_service_from.view - aft::starting_view_change !=
        newest.endorsement_epoch_end->view ||
      current_service_from.seqno - 1 != newest.endorsement_epoch_end->seqno)
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, the current service "
        "start at {} is not chained with previous endorsement ending at {}",
        current_service_from.to_str(),
        newest.endorsement_epoch_end->to_str()));
    }
  }
}
