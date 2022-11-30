// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "js/wrap.cpp"

#include <doctest/doctest.h>

TEST_CASE("Check KV Map access")
{
  using namespace ccf::js;

  {
    INFO("In application context");
    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        _check_kv_map_access(
          ccf::js::TxAccess::APP, "public:ccf.internal.table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace are read-only");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::APP, "ccf.internal.table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::APP, "public:ccf.gov.table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace are read-only");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::APP, "ccf.gov.table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Public application tables are read-write");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::APP, "public:table") ==
        MapAccessDecision::READ_WRITE);
    }

    {
      INFO("Private application tables are read-write");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::APP, "table") ==
        MapAccessDecision::READ_WRITE);
    }
  }

  {
    INFO("In read-only governance context (ballot, validate, resolve)");
    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        _check_kv_map_access(
          ccf::js::TxAccess::GOV_RO, "public:ccf.internal.table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::GOV_RO, "ccf.internal.table") ==
        MapAccessDecision::ILLEGAL);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        _check_kv_map_access(
          ccf::js::TxAccess::GOV_RO, "public:ccf.gov.table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::GOV_RO, "ccf.gov.table") ==
        MapAccessDecision::ILLEGAL);
    }

    {
      INFO("Public application tables are read-only");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::GOV_RO, "public:table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private application cannot even be read");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::GOV_RO, "table") ==
        MapAccessDecision::ILLEGAL);
    }
  }

  {
    INFO("In read-write governance context (apply)");

    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        _check_kv_map_access(
          ccf::js::TxAccess::GOV_RW, "public:ccf.internal.table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::GOV_RO, "ccf.internal.table") ==
        MapAccessDecision::ILLEGAL);
    }

    {
      INFO("Governance tables are read-write");
      REQUIRE(
        _check_kv_map_access(
          ccf::js::TxAccess::GOV_RW, "public:ccf.gov.table") ==
        MapAccessDecision::READ_WRITE);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::GOV_RO, "ccf.gov.table") ==
        MapAccessDecision::ILLEGAL);
    }

    {
      INFO("Public applications tables are read-only");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::GOV_RW, "public:table") ==
        MapAccessDecision::READ_ONLY);
    }

    {
      INFO("Private applications tables cannot even be read");
      REQUIRE(
        _check_kv_map_access(ccf::js::TxAccess::GOV_RW, "table") ==
        MapAccessDecision::ILLEGAL);
    }
  }
}