// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/map_access_permissions.h"
#include "ccf/js/namespace_restrictions.h"
#include "ccf/js/tx_access.h"
#include "kv/kv_types.h"

namespace ccf::js
{
  static MapAccessPermissions check_kv_map_access(
    TxAccess execution_context, const std::string& table_name)
  {
    // Enforce the restrictions described in the read_write_restrictions page in
    // the docs. Note that table is more readable, so should be considered the
    // source of truth for these restrictions. This code is formatted to attempt
    // to make it clear how it maps directly to that table.
    const auto [privacy_of_table, namespace_of_table] =
      kv::parse_map_name(table_name);

    switch (privacy_of_table)
    {
      case (kv::SecurityDomain::PRIVATE):
      {
        // The only time private tables can be used, is on private application
        // tables in an application context. Governance should neither read from
        // nor write to private tables, and if private governance or internal
        // tables exist then applications should not be able to read them.
        if (
          execution_context == TxAccess::APP_RW &&
          namespace_of_table == kv::AccessCategory::APPLICATION)
        {
          return MapAccessPermissions::READ_WRITE;
        }
        else if (
          execution_context == TxAccess::APP_RO &&
          namespace_of_table == kv::AccessCategory::APPLICATION)
        {
          return MapAccessPermissions::READ_ONLY;
        }
        else
        {
          return MapAccessPermissions::ILLEGAL;
        }
      }

      case (kv::SecurityDomain::PUBLIC):
      {
        switch (namespace_of_table)
        {
          case kv::AccessCategory::INTERNAL:
          {
            return MapAccessPermissions::READ_ONLY;
          }

          case kv::AccessCategory::GOVERNANCE:
          {
            if (execution_context == TxAccess::GOV_RW)
            {
              return MapAccessPermissions::READ_WRITE;
            }
            else
            {
              return MapAccessPermissions::READ_ONLY;
            }
          }

          case kv::AccessCategory::APPLICATION:
          {
            switch (execution_context)
            {
              case (TxAccess::APP_RW):
              {
                return MapAccessPermissions::READ_WRITE;
              }
              case (TxAccess::APP_RO):
              {
                return MapAccessPermissions::READ_ONLY;
              }
              default:
              {
                return MapAccessPermissions::ILLEGAL;
              }
            }
          }
        }
      }

      case (kv::SecurityDomain::SECURITY_DOMAIN_MAX):
      {
        throw std::logic_error(fmt::format(
          "Unexpected security domain (max) for table {}", table_name));
      }
    }
  }

  static MapAccessPermissions calculate_namespace_restrictions(
    MapAccessPermissions current,
    const NamespaceRestrictions& restrictions,
    const std::string& map_name)
  {
    for (const auto& restriction : restrictions)
    {
      if (std::regex_match(map_name, restriction.regex))
      {
        current = std::max(current, restriction.permission);
      }

      // If we reach maximally restricted permission (ILLEGAL), then we cannot
      // get _more_ restricted, so safe to break
      if (current == MapAccessPermissions::ILLEGAL)
      {
        break;
      }
    }

    return current;
  }

  static MapAccessPermissions check_kv_map_access_with_namespace_restrictions(
    TxAccess execution_context,
    const NamespaceRestrictions& restrictions,
    const std::string& table_name)
  {
    auto access = check_kv_map_access(execution_context, table_name);
    access = calculate_namespace_restrictions(access, restrictions, table_name);
    return access;
  }
}
