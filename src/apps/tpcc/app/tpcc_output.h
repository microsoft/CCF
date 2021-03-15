// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdint.h>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "tpcc_tables.h"

namespace tpcc
{
  struct PaymentOutput
  {
    // TPC-C 2.5.3.4 specifies these output fields
    std::array<char, Address::MAX_STREET + 1> w_street_1;
    std::array<char, Address::MAX_STREET + 1> w_street_2;
    std::array<char, Address::MAX_CITY + 1> w_city;
    std::array<char, Address::STATE + 1> w_state;
    std::array<char, Address::ZIP + 1> w_zip;

    std::array<char, Address::MAX_STREET + 1> d_street_1;
    std::array<char, Address::MAX_STREET + 1> d_street_2;
    std::array<char, Address::MAX_CITY + 1> d_city;
    std::array<char, Address::STATE + 1> d_state;
    std::array<char, Address::ZIP + 1> d_zip;

    float c_credit_lim;
    float c_discount;
    float c_balance;
    std::array<char, Customer::MAX_FIRST + 1> c_first;
    std::array<char, Customer::MIDDLE + 1> c_middle;
    std::array<char, Customer::MAX_LAST + 1> c_last;
    std::array<char, Address::MAX_STREET + 1> c_street_1;
    std::array<char, Address::MAX_STREET + 1> c_street_2;
    std::array<char, Address::MAX_CITY + 1> c_city;
    std::array<char, Address::STATE + 1> c_state;
    std::array<char, Address::ZIP + 1> c_zip;
    std::array<char, Customer::PHONE + 1> c_phone;
    std::array<char, DATETIME_SIZE + 1> c_since;
    std::array<char, Customer::CREDIT + 1> c_credit;
    std::array<char, Customer::MAX_DATA + 1> c_data;
  };

  struct DeliveryOrderInfo
  {
    int32_t d_id;
    int32_t o_id;
  };

  struct OrderStatusOutput
  {
    int32_t c_id;
    float c_balance;

    int32_t o_id;
    int32_t o_carrier_id;

    struct OrderLineSubset
    {
      int32_t i_id;
      int32_t supply_w_id;
      int32_t quantity;
      float amount;
      std::array<char, DATETIME_SIZE + 1> delivery_d;
    };

    std::vector<OrderLineSubset> lines;
    std::array<char, Customer::MAX_FIRST + 1> c_first;
    std::array<char, Customer::MIDDLE + 1> c_middle;
    std::array<char, Customer::MAX_LAST + 1> c_last;
    std::array<char, DATETIME_SIZE + 1> o_entry_d;
  };

  struct NewOrderItem
  {
    int32_t i_id;
    int32_t ol_supply_w_id;
    int32_t ol_quantity;
  };

  struct NewOrderOutput
  {
    NewOrderOutput() : w_tax(0), d_tax(0), o_id(0), c_discount(0), total(0)
    {
      std::fill(c_last.begin(), c_last.end(), 0);
      std::fill(c_credit.begin(), c_credit.end(), 0);
      std::fill(status.begin(), status.end(), 0);
    }

    float w_tax;
    float d_tax;
    int32_t o_id;
    float c_discount;
    float total;

    struct ItemInfo
    {
      static const char BRAND = 'B';
      static const char GENERIC = 'G';

      int32_t s_quantity;
      float i_price;
      float ol_amount;
      char brand_generic;
      std::array<char,Item::MAX_NAME + 1> i_name;

    };

    std::vector<ItemInfo> items;
    std::array<char, Customer::MAX_LAST + 1> c_last;
    std::array<char, Customer::CREDIT + 1> c_credit;

    static const int MAX_STATUS = 25;
    static const char INVALID_ITEM_STATUS[];
    std::array<char,MAX_STATUS + 1> status;
  };
}