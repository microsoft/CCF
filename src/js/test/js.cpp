// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/permissions_checks.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <random>

TEST_CASE("Check KV Map access")
{
  using namespace ccf::js;
  constexpr auto public_internal_table_name = "public:ccf.internal.table";
  constexpr auto private_internal_table_name = "ccf.internal.table";

  constexpr auto public_gov_table_name = "public:ccf.gov.table";
  constexpr auto private_gov_table_name = "ccf.gov.table";

  constexpr auto public_app_table_name = "public:table";
  constexpr auto private_app_table_name = "table";
  {
    INFO("In application context");
    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, public_internal_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_internal_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, public_gov_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_gov_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public application tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, public_app_table_name) ==
        KVAccessPermissions::READ_WRITE);

      {
        INFO(
          "Unless the operation is read-only, in which case they're read-only");
        REQUIRE(
          check_kv_map_access(TxAccess::APP_RO, public_app_table_name) ==
          KVAccessPermissions::READ_ONLY);
      }
    }

    {
      INFO("Private application tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_app_table_name) ==
        KVAccessPermissions::READ_WRITE);

      {
        INFO(
          "Unless the operation is read-only, in which case they're read-only");
        REQUIRE(
          check_kv_map_access(TxAccess::APP_RO, private_app_table_name) ==
          KVAccessPermissions::READ_ONLY);
      }
    }
  }

  {
    INFO("In read-only governance context (ballot, validate, resolve)");
    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_internal_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_internal_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_gov_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_gov_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public application cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_app_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Private application cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_app_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }
  }

  {
    INFO("In read-write governance context (apply)");

    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_internal_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_internal_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_gov_table_name) ==
        KVAccessPermissions::READ_WRITE);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_gov_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public applications tables cannot be read, but CAN be written to");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_app_table_name) ==
        KVAccessPermissions::WRITE_ONLY);
    }

    {
      INFO("Private applications tables cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_app_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }
  }
}
