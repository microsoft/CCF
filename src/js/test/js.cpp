// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "js/wrap.cpp"

#include <doctest/doctest.h>

TEST_CASE("Check KV Map access")
{
  // TODO: Update all of these
  INFO("Application context");
  {
    // Governance tables are read-only
    REQUIRE(
      _check_kv_map_access(ccf::js::TxAccess::APP, "public:ccf.gov.table"));
    // Public internal tables are read-only
    REQUIRE(_check_kv_map_access(
      ccf::js::TxAccess::APP, "public:ccf.internal.table"));
    // Public applications tables are read-write
    REQUIRE(!_check_kv_map_access(ccf::js::TxAccess::APP, "public:table"));
    // Private applications tables are read-write
    REQUIRE(!_check_kv_map_access(ccf::js::TxAccess::APP, "table"));
  }

  INFO("Read-only governance context (ballot, resolve)");
  {
    // Governance tables are read-only
    REQUIRE(
      _check_kv_map_access(ccf::js::TxAccess::GOV_RO, "public:ccf.gov.table"));
    // Public internal tables are read-only
    REQUIRE(_check_kv_map_access(
      ccf::js::TxAccess::GOV_RO, "public:ccf.internal.table"));
    // Public applications tables are read-only
    REQUIRE(_check_kv_map_access(ccf::js::TxAccess::GOV_RO, "public:table"));
    // Private applications tables are read-only
    REQUIRE(_check_kv_map_access(ccf::js::TxAccess::GOV_RO, "table"));
  }

  INFO("Read-write governance context (apply)");
  {
    // Governance tables are read-write
    REQUIRE(
      !_check_kv_map_access(ccf::js::TxAccess::GOV_RW, "public:ccf.gov.table"));
    // Public internal tables are read-only
    REQUIRE(_check_kv_map_access(
      ccf::js::TxAccess::GOV_RW, "public:ccf.internal.table"));
    // Public applications tables are read-only
    REQUIRE(_check_kv_map_access(ccf::js::TxAccess::GOV_RW, "public:table"));
    // Private applications tables are read-only
    REQUIRE(_check_kv_map_access(ccf::js::TxAccess::GOV_RW, "table"));
  }

  INFO("No access to internal private tables from any JS context");
  {
    REQUIRE_THROWS_AS(
      _check_kv_map_access(ccf::js::TxAccess::APP, "ccf.internal"),
      std::logic_error);
    REQUIRE_THROWS_AS(
      _check_kv_map_access(ccf::js::TxAccess::GOV_RO, "ccf.internal"),
      std::logic_error);
    REQUIRE_THROWS_AS(
      _check_kv_map_access(ccf::js::TxAccess::GOV_RW, "ccf.internal"),
      std::logic_error);
  }
}