// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "js/wrap.cpp"

#include <doctest/doctest.h>

using namespace ccf::js;
MapAccessDecision test_access(TxAccess exec_context, char const* table_name)
{
  return std::get<0>(_check_kv_map_access(exec_context, table_name));
}

TEST_CASE("Check KV Map access")
{
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
        test_access(TxAccess::APP, public_internal_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace are read-only");
      REQUIRE(
        test_access(TxAccess::APP, private_internal_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        test_access(TxAccess::APP, public_gov_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace are read-only");
      REQUIRE(
        test_access(TxAccess::APP, private_gov_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Public application tables are read-write");
      REQUIRE(
        test_access(TxAccess::APP, public_app_table_name) ==
        MapAccessDecision::READ_WRITE);
    }

    {
      INFO("Private application tables are read-write");
      REQUIRE(
        test_access(TxAccess::APP, private_app_table_name) ==
        MapAccessDecision::READ_WRITE);
    }
  }

  {
    INFO("In read-only governance context (ballot, validate, resolve)");
    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        test_access(TxAccess::GOV_RO, public_internal_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        test_access(TxAccess::GOV_RO, private_internal_table_name) ==
        MapAccessDecision::ILLEGAL);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        test_access(TxAccess::GOV_RO, public_gov_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        test_access(TxAccess::GOV_RO, private_gov_table_name) ==
        MapAccessDecision::ILLEGAL);
    }

    {
      INFO("Public application tables are read-only");
      REQUIRE(
        test_access(TxAccess::GOV_RO, public_app_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private application cannot even be read");
      REQUIRE(
        test_access(TxAccess::GOV_RO, private_app_table_name) ==
        MapAccessDecision::ILLEGAL);
    }
  }

  {
    INFO("In read-write governance context (apply)");

    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        test_access(TxAccess::GOV_RW, public_internal_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        test_access(TxAccess::GOV_RW, private_internal_table_name) ==
        MapAccessDecision::ILLEGAL);
    }

    {
      INFO("Governance tables are read-write");
      REQUIRE(
        test_access(TxAccess::GOV_RW, public_gov_table_name) ==
        MapAccessDecision::READ_WRITE);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        test_access(TxAccess::GOV_RW, private_gov_table_name) ==
        MapAccessDecision::ILLEGAL);
    }

    {
      INFO("Public applications tables are read-only");
      REQUIRE(
        test_access(TxAccess::GOV_RW, public_app_table_name) ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private applications tables cannot even be read");
      REQUIRE(
        test_access(TxAccess::GOV_RW, private_app_table_name) ==
        MapAccessDecision::ILLEGAL);
    }
  }
}