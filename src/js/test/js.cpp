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
        MapAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_internal_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, public_gov_table_name) ==
        MapAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_gov_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public application tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, public_app_table_name) ==
        MapAccessPermissions::READ_WRITE);

      {
        INFO(
          "Unless the operation is read-only, in which case they're read-only");
        REQUIRE(
          check_kv_map_access(TxAccess::APP_RO, public_app_table_name) ==
          MapAccessPermissions::READ_ONLY);
      }
    }

    {
      INFO("Private application tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_app_table_name) ==
        MapAccessPermissions::READ_WRITE);

      {
        INFO(
          "Unless the operation is read-only, in which case they're read-only");
        REQUIRE(
          check_kv_map_access(TxAccess::APP_RO, private_app_table_name) ==
          MapAccessPermissions::READ_ONLY);
      }
    }
  }

  {
    INFO("In read-only governance context (ballot, validate, resolve)");
    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_internal_table_name) ==
        MapAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_internal_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_gov_table_name) ==
        MapAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_gov_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public application cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_app_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }

    {
      INFO("Private application cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_app_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }
  }

  {
    INFO("In read-write governance context (apply)");

    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_internal_table_name) ==
        MapAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_internal_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_gov_table_name) ==
        MapAccessPermissions::READ_WRITE);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_gov_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public applications tables cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_app_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }

    {
      INFO("Private applications tables cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_app_table_name) ==
        MapAccessPermissions::ILLEGAL);
    }
  }
}

TEST_CASE("Check KV Map namespace restrictions")
{
  using namespace ccf::js;

  constexpr auto RW = MapAccessPermissions::READ_WRITE;
  constexpr auto RO = MapAccessPermissions::READ_ONLY;
  constexpr auto ILL = MapAccessPermissions::ILLEGAL;

  NamespaceRestriction ro_nr;
  ro_nr.regex = std::regex(".*bar.*");
  ro_nr.permission = RO;

  NamespaceRestriction ill_nr;
  ill_nr.regex = std::regex(".*baz.*");
  ill_nr.permission = ILL;

  {
    INFO("With a single read-only namespace restriction");
    NamespaceRestrictions restrictions{ro_nr};

    {
      INFO("Non-matching tables are unaffected");
      REQUIRE(
        calculate_namespace_restrictions(RW, restrictions, "any.other.table") ==
        RW);
    }

    {
      INFO("Matching tables may become more restricted");
      REQUIRE(calculate_namespace_restrictions(RW, restrictions, "bar") == RO);
      REQUIRE(
        calculate_namespace_restrictions(RW, restrictions, "foobar") == RO);
      REQUIRE(
        calculate_namespace_restrictions(RW, restrictions, "barfoo") == RO);
      REQUIRE(
        calculate_namespace_restrictions(RW, restrictions, "foobarfoo") == RO);
    }

    {
      INFO("Tables cannot become less restricted");
      REQUIRE(
        calculate_namespace_restrictions(RO, restrictions, "any.other.table") ==
        RO);

      REQUIRE(
        calculate_namespace_restrictions(ILL, restrictions, "bar") == ILL);
    }
  }

  {
    INFO("With a single illegal namespace restriction");
    NamespaceRestrictions restrictions{ill_nr};

    {
      INFO("Non-matching tables are unaffected");
      REQUIRE(
        calculate_namespace_restrictions(RW, restrictions, "any.other.table") ==
        RW);
    }

    {
      INFO("Matching tables may become more restricted");
      for (auto current : {RW, RO})
      {
        REQUIRE(
          calculate_namespace_restrictions(current, restrictions, "baz") ==
          ILL);
        REQUIRE(
          calculate_namespace_restrictions(current, restrictions, "foobaz") ==
          ILL);
        REQUIRE(
          calculate_namespace_restrictions(current, restrictions, "bazfoo") ==
          ILL);
        REQUIRE(
          calculate_namespace_restrictions(
            current, restrictions, "foobazfoo") == ILL);
      }
    }

    {
      INFO("Tables cannot become less restricted");
      REQUIRE(
        calculate_namespace_restrictions(RO, restrictions, "any.other.table") ==
        RO);

      REQUIRE(
        calculate_namespace_restrictions(ILL, restrictions, "baz") == ILL);
    }
  }

  {
    INFO("With multiple namespace restrictions");

    NamespaceRestriction ro_nr2;
    ro_nr2.regex = std::regex(".*bur.*");
    ro_nr2.permission = RO;

    NamespaceRestriction ill_nr2;
    ill_nr2.regex = std::regex(".*buz.*");
    ill_nr2.permission = ILL;

    NamespaceRestrictions restrictions{ro_nr, ro_nr2, ill_nr, ill_nr2};

    std::random_device rd;
    std::mt19937 g(rd());

    for (size_t i = 0; i < 10; ++i)
    {
      INFO("Regardless of restriction order");
      std::shuffle(restrictions.begin(), restrictions.end(), g);

      {
        INFO("Non-matching tables are unaffected");
        REQUIRE(
          calculate_namespace_restrictions(
            RW, restrictions, "any.other.table") == RW);
      }

      {
        INFO("Matching tables may become more restricted");
        REQUIRE(
          calculate_namespace_restrictions(RW, restrictions, "bar") == RO);
        REQUIRE(
          calculate_namespace_restrictions(RW, restrictions, "bur") == RO);
        REQUIRE(
          calculate_namespace_restrictions(RW, restrictions, "baz") == ILL);
        REQUIRE(
          calculate_namespace_restrictions(RW, restrictions, "buz") == ILL);

        REQUIRE(
          calculate_namespace_restrictions(RW, restrictions, "fooburfoo") ==
          RO);
        REQUIRE(
          calculate_namespace_restrictions(RW, restrictions, "foobarburfoo") ==
          RO);
        REQUIRE(
          calculate_namespace_restrictions(RW, restrictions, "foobuzfoo") ==
          ILL);
        REQUIRE(
          calculate_namespace_restrictions(RW, restrictions, "foobarbuzfoo") ==
          ILL);
      }

      {
        INFO("Tables cannot become less restricted");
        REQUIRE(
          calculate_namespace_restrictions(
            RO, restrictions, "any.other.table") == RO);
        REQUIRE(
          calculate_namespace_restrictions(
            ILL, restrictions, "any.other.table") == ILL);
      }
    }
  }
}