// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/kv_access_permissions.h"
#include "ccf/js/namespace_restrictions.h"
#include "ccf/js/tx_access.h"
#include "kv/kv_types.h"

namespace ccf::js
{
  static KVAccessPermissions check_kv_map_access(
    TxAccess execution_context, const std::string& table_name)
  {
    // Enforce the restrictions described in the read_write_restrictions page in
    // the docs. Note that table is more readable, so should be considered the
    // source of truth for these restrictions. This code is formatted to attempt
    // to make it clear how it maps directly to that table.
    const auto [privacy_of_table, namespace_of_table] =
      ccf::kv::parse_map_name(table_name);

    switch (privacy_of_table)
    {
      case (ccf::kv::SecurityDomain::PRIVATE):
      {
        // The only time private tables can be used, is on private application
        // tables in an application context. Governance should neither read from
        // nor write to private tables, and if private governance or internal
        // tables exist then applications should not be able to read them.
        if (
          execution_context == TxAccess::APP_RW &&
          namespace_of_table == ccf::kv::AccessCategory::APPLICATION)
        {
          return KVAccessPermissions::READ_WRITE;
        }

        if (
          execution_context == TxAccess::APP_RO &&
          namespace_of_table == ccf::kv::AccessCategory::APPLICATION)
        {
          return KVAccessPermissions::READ_ONLY;
        }

        return KVAccessPermissions::ILLEGAL;
      }

      case (ccf::kv::SecurityDomain::PUBLIC):
      {
        switch (namespace_of_table)
        {
          case ccf::kv::AccessCategory::INTERNAL:
          {
            return KVAccessPermissions::READ_ONLY;
          }

          case ccf::kv::AccessCategory::GOVERNANCE:
          {
            if (execution_context == TxAccess::GOV_RW)
            {
              return KVAccessPermissions::READ_WRITE;
            }

            return KVAccessPermissions::READ_ONLY;
          }

          case ccf::kv::AccessCategory::APPLICATION:
          {
            switch (execution_context)
            {
              case (TxAccess::APP_RW):
              {
                return KVAccessPermissions::READ_WRITE;
              }
              case (TxAccess::APP_RO):
              {
                return KVAccessPermissions::READ_ONLY;
              }
              case (TxAccess::GOV_RW):
              {
                return KVAccessPermissions::WRITE_ONLY;
              }
              default:
              {
                return KVAccessPermissions::ILLEGAL;
              }
            }
          }
        }
      }

      case (ccf::kv::SecurityDomain::SECURITY_DOMAIN_MAX):
      {
        throw std::logic_error(fmt::format(
          "Unexpected security domain (max) for table {}", table_name));
      }
    }
  }
  static std::string explain_kv_map_access(
    ccf::js::KVAccessPermissions permission, ccf::js::TxAccess access)
  {
    char const* table_kind = permission == KVAccessPermissions::READ_ONLY ?
      "read-only" :
      (permission == KVAccessPermissions::WRITE_ONLY ? "write-only" :
                                                       "inaccessible");

    char const* exec_context = nullptr;
    switch (access)
    {
      case (TxAccess::APP_RW):
      {
        exec_context = "application";
        break;
      }
      case (TxAccess::APP_RO):
      {
        exec_context = "read-only application";
        break;
      }
      case (TxAccess::GOV_RO):
      {
        exec_context = "read-only governance";
        break;
      }
      case (TxAccess::GOV_RW):
      {
        exec_context = "read-write governance";
        break;
      }
      default:
      {
        exec_context = "unknown";
        break;
      }
    }

    static constexpr char const* access_permissions_explanation_url =
      "https://microsoft.github.io/CCF/main/audit/"
      "read_write_restrictions.html";

    return fmt::format(
      "This table is {} in current ({}) execution context. See {} for more "
      "detail.",
      table_kind,
      exec_context,
      access_permissions_explanation_url);
  }
}
