// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdint.h>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

//#include "ds/json.h"
#include <nlohmann/json.hpp>
namespace tpcc
{
  // Just a container for constants
  struct Address
  {
    // TODO: Embed this structure in warehouse, district, customer? This would
    // reduce some duplication, but would also change the field names
    static const int MIN_STREET = 10;
    static const int MAX_STREET = 20;
    static const int MIN_CITY = 10;
    static const int MAX_CITY = 20;
    static const int STATE = 2;
    static const int ZIP = 9;

    static void copy(
      char* street1,
      char* street2,
      char* city,
      char* state,
      char* zip,
      const char* src_street1,
      const char* src_street2,
      const char* src_city,
      const char* src_state,
      const char* src_zip);

  private:
    Address();
  };

  struct Item
  {
    static const int MIN_IM = 1;
    static const int MAX_IM = 10000;
    static constexpr float MIN_PRICE = 1.00;
    static constexpr float MAX_PRICE = 100.00;
    static const int MIN_NAME = 14;
    static const int MAX_NAME = 24;
    static const int MIN_DATA = 26;
    static const int MAX_DATA = 50;
    static const int NUM_ITEMS = 100000;

    int32_t i_id;
    int32_t i_im_id;
    float i_price;
    std::array<char, MAX_NAME + 1> i_name;
    std::array<char, MAX_DATA + 1> i_data;

    MSGPACK_DEFINE(i_id, i_im_id, i_price, i_name, i_data);
  };
  DECLARE_JSON_TYPE(Item);
  DECLARE_JSON_REQUIRED_FIELDS(Item, i_id, i_im_id, i_price, i_name, i_data);

  struct Warehouse
  {
    static constexpr float MIN_TAX = 0;
    static constexpr float MAX_TAX = 0.2000f;
    static constexpr float INITIAL_YTD = 300000.00f;
    static const int MIN_NAME = 6;
    static const int MAX_NAME = 10;
    // TPC-C 1.3.1 (page 11) requires 2*W. This permits testing up to 50
    // warehouses. This is an arbitrary limit created to pack ids into integers.
    static const int MAX_WAREHOUSE_ID = 100;
    struct Key
    {
      int32_t w_id;
      MSGPACK_DEFINE(w_id);
    };

    Key get_key()
    {
      return {w_id};
    }

    int32_t w_id;
    float w_tax;
    float w_ytd;
    std::array<char,MAX_NAME + 1> w_name;
    std::array<char,Address::MAX_STREET + 1> w_street_1;
    std::array<char,Address::MAX_STREET + 1> w_street_2;
    std::array<char,Address::MAX_STREET + 1> w_city;
    std::array<char,Address::STATE + 1> w_state;
    std::array<char,Address::ZIP + 1> w_zip;

    MSGPACK_DEFINE(
      w_id,
      w_tax,
      w_ytd,
      w_name,
      w_street_1,
      w_street_2,
      w_city,
      w_state,
      w_zip);
  };
  DECLARE_JSON_TYPE(Warehouse::Key);
  DECLARE_JSON_REQUIRED_FIELDS(Warehouse::Key, w_id);
  DECLARE_JSON_TYPE(Warehouse);
  DECLARE_JSON_REQUIRED_FIELDS(
    Warehouse,
    w_id,
    w_tax,
    w_ytd,
    w_name,
    w_street_1,
    w_street_2,
    w_city,
    w_state,
    w_zip);

  struct District
  {
    static constexpr float MIN_TAX = 0;
    static constexpr float MAX_TAX = 0.2000f;
    static constexpr float INITIAL_YTD = 30000.00; // different from Warehouse
    static const int INITIAL_NEXT_O_ID = 3001;
    static const int MIN_NAME = 6;
    static const int MAX_NAME = 10;
    static const int NUM_PER_WAREHOUSE = 10;

    struct Key
    {
      int32_t d_id;
      int32_t d_w_id;
      MSGPACK_DEFINE(d_id, d_w_id);
    };

    int32_t d_id;
    int32_t d_w_id;
    float d_tax;
    float d_ytd;
    int32_t d_next_o_id;
    std::array<char, MAX_NAME + 1> d_name;
    std::array<char, Address::MAX_STREET + 1> d_street_1;
    std::array<char, Address::MAX_STREET + 1> d_street_2;
    std::array<char, Address::MAX_CITY + 1> d_city;
    std::array<char, Address::STATE + 1> d_state;
    std::array<char, Address::ZIP + 1> d_zip;

    Key get_key()
    {
      return {d_id, d_w_id};
    }

    MSGPACK_DEFINE(
      d_id,
      d_w_id,
      d_tax,
      d_ytd,
      d_next_o_id,
      d_name,
      d_street_1,
      d_street_2,
      d_city,
      d_state,
      d_zip);
  };
  DECLARE_JSON_TYPE(District::Key);
  DECLARE_JSON_REQUIRED_FIELDS(District::Key, d_id, d_w_id);
  DECLARE_JSON_TYPE(District);
  DECLARE_JSON_REQUIRED_FIELDS(
    District,
    d_id,
    d_w_id,
    d_tax,
    d_ytd,
    d_next_o_id,
    d_name,
    d_street_1,
    d_street_2,
    d_city,
    d_state,
    d_zip);

  struct Stock
  {
    static const int MIN_QUANTITY = 10;
    static const int MAX_QUANTITY = 100;
    static const int DIST = 24;
    static const int MIN_DATA = 26;
    static const int MAX_DATA = 50;
    static const int NUM_STOCK_PER_WAREHOUSE = 100000;

    int32_t s_i_id;
    int32_t s_w_id;
    int32_t s_quantity;
    int32_t s_ytd;
    int32_t s_order_cnt;
    int32_t s_remote_cnt;
    std::array<std::array<char, DIST + 1>, District::NUM_PER_WAREHOUSE> s_dist;
    std::array<char, MAX_DATA + 1> s_data;

    Stock() = default;

    struct Key
    {
      int32_t s_i_id;
      int32_t s_w_id;
      MSGPACK_DEFINE(s_i_id, s_w_id);
    };

    Key get_key()
    {
      return {s_w_id, s_i_id};
    }

    MSGPACK_DEFINE(
      s_i_id,
      s_w_id,
      s_quantity,
      s_ytd,
      s_order_cnt,
      s_remote_cnt,
      s_dist,
      s_data);
  };
  DECLARE_JSON_TYPE(Stock::Key);
  DECLARE_JSON_REQUIRED_FIELDS(Stock::Key, s_i_id, s_w_id);
  DECLARE_JSON_TYPE(Stock);
  DECLARE_JSON_REQUIRED_FIELDS(
    Stock,
    s_i_id,
    s_w_id,
    s_quantity,
    s_ytd,
    s_order_cnt,
    s_remote_cnt,
    s_dist,
    s_data
  );

  // YYYY-MM-DD HH:MM:SS This is supposed to be a date/time field from Jan 1st
  // 1900 - Dec 31st 2100 with a resolution of 1 second. See TPC-C 1.3.1.
  static const int DATETIME_SIZE = 14;

  struct Customer
  {
    static constexpr float INITIAL_CREDIT_LIM = 50000.00;
    static constexpr float MIN_DISCOUNT = 0.0000;
    static constexpr float MAX_DISCOUNT = 0.5000;
    static constexpr float INITIAL_BALANCE = -10.00;
    static constexpr float INITIAL_YTD_PAYMENT = 10.00;
    static const int INITIAL_PAYMENT_CNT = 1;
    static const int INITIAL_DELIVERY_CNT = 0;
    static const int MIN_FIRST = 6;
    static const int MAX_FIRST = 10;
    static const int MIDDLE = 2;
    static const int MAX_LAST = 16;
    static const int PHONE = 16;
    static const int CREDIT = 2;
    static const int MIN_DATA = 300;
    static const int MAX_DATA = 500;
    static const int NUM_PER_DISTRICT = 3000;
    static constexpr char GOOD_CREDIT[] = "GC";
    static constexpr char BAD_CREDIT[] = "BC";

    struct Key
    {
      int32_t c_id;
      int32_t c_d_id;
      int32_t c_w_id;
      MSGPACK_DEFINE(c_id, c_d_id, c_w_id);
    };

    Key get_key()
    {
      return {c_id, c_d_id, c_w_id};
    }

    int32_t c_id;
    int32_t c_d_id;
    int32_t c_w_id;
    float c_credit_lim;
    float c_discount;
    float c_balance;
    float c_ytd_payment;
    int32_t c_payment_cnt;
    int32_t c_delivery_cnt;
    std::array<char,MAX_FIRST + 1> c_first;
    std::array<char,MIDDLE + 1> c_middle;
    std::array<char,MAX_LAST + 1> c_last;
    std::array<char, Address::MAX_STREET + 1> c_street_1;
    std::array<char, Address::MAX_STREET + 1> c_street_2;
    std::array<char, Address::MAX_CITY + 1> c_city;
    std::array<char, Address::STATE + 1> c_state;
    std::array<char, Address::ZIP + 1> c_zip;
    std::array<char, PHONE + 1> c_phone;
    std::array<char, DATETIME_SIZE + 1> c_since;
    std::array<char, CREDIT + 1> c_credit;
    std::array<char, MAX_DATA + 1> c_data;

    MSGPACK_DEFINE(
      c_id,
      c_d_id,
      c_w_id,
      c_credit_lim,
      c_discount,
      c_balance,
      c_ytd_payment,
      c_payment_cnt,
      c_delivery_cnt,
      c_first,
      c_middle,
      c_last,
      c_street_1,
      c_street_2,
      c_city,
      c_state,
      c_zip,
      c_phone,
      c_since,
      c_credit,
      c_data);
  };
  DECLARE_JSON_TYPE(Customer::Key);
  DECLARE_JSON_REQUIRED_FIELDS(
    Customer::Key,
    c_id,
    c_d_id,
    c_w_id);
  DECLARE_JSON_TYPE(Customer);
  DECLARE_JSON_REQUIRED_FIELDS(
    Customer,
    c_id,
    c_d_id,
    c_w_id,
    c_credit_lim,
    c_discount,
    c_balance,
    c_ytd_payment,
    c_payment_cnt,
    c_delivery_cnt,
    c_first,
    c_middle,
    c_last,
    c_street_1,
    c_street_2,
    c_city,
    c_state,
    c_zip,
    c_phone,
    c_since,
    c_credit,
    c_data);

  struct Order
  {
    static const int MIN_CARRIER_ID = 1;
    static const int MAX_CARRIER_ID = 10;
    // HACK: This is not strictly correct, but it works
    static const int NULL_CARRIER_ID = 0;
    // Less than this value, carrier != null, >= -> carrier == null
    static const int NULL_CARRIER_LOWER_BOUND = 2101;
    static const int MIN_OL_CNT = 5;
    static const int MAX_OL_CNT = 15;
    static const int INITIAL_ALL_LOCAL = 1;
    static const int INITIAL_ORDERS_PER_DISTRICT = 3000;
    // See TPC-C 1.3.1 (page 15)
    static const int MAX_ORDER_ID = 10000000;

    struct Key
    {
      int32_t o_id;
      int32_t o_d_id;
      int32_t o_w_id;
      MSGPACK_DEFINE(o_id, o_d_id, o_w_id);
    };

    Key get_key()
    {
      return {o_id, o_d_id, o_w_id};
    }

    int32_t o_id;
    int32_t o_c_id;
    int32_t o_d_id;
    int32_t o_w_id;
    int32_t o_carrier_id;
    int32_t o_ol_cnt;
    int32_t o_all_local;
    std::array<char, DATETIME_SIZE + 1> o_entry_d;

    MSGPACK_DEFINE(
      o_id,
      o_c_id,
      o_d_id,
      o_w_id,
      o_carrier_id,
      o_ol_cnt,
      o_all_local,
      o_entry_d);
  };
  DECLARE_JSON_TYPE(Order::Key);
  DECLARE_JSON_REQUIRED_FIELDS(
    Order::Key, o_id, o_d_id, o_w_id);
  DECLARE_JSON_TYPE(Order);
  DECLARE_JSON_REQUIRED_FIELDS(
    Order,
    o_id,
    o_c_id,
    o_d_id,
    o_w_id,
    o_carrier_id,
    o_ol_cnt,
    o_all_local,
    o_entry_d);

  struct OrderLine
  {
    static const int MIN_I_ID = 1;
    static const int MAX_I_ID = 100000; // Item::NUM_ITEMS
    static const int INITIAL_QUANTITY = 5;
    static constexpr float MIN_AMOUNT = 0.01f;
    static constexpr float MAX_AMOUNT = 9999.99f;
    // new order has 10/1000 probability of selecting a remote warehouse for
    // ol_supply_w_id
    static const int REMOTE_PROBABILITY_MILLIS = 10;

    struct Key
    {
      int32_t ol_o_id;
      int32_t ol_d_id;
      int32_t ol_w_id;
      int32_t ol_number;
      MSGPACK_DEFINE(
        ol_o_id, ol_d_id, ol_w_id, ol_number);
    };

    Key get_key()
    {
      return {ol_o_id, ol_d_id, ol_w_id, ol_number};
    }

    int32_t ol_o_id;
    int32_t ol_d_id;
    int32_t ol_w_id;
    int32_t ol_number;
    int32_t ol_i_id;
    int32_t ol_supply_w_id;
    int32_t ol_quantity;
    float ol_amount;
    std::array<char, DATETIME_SIZE + 1> ol_delivery_d;
    std::array<char, Stock::DIST + 1> ol_dist_info;

    MSGPACK_DEFINE(
      ol_o_id,
      ol_d_id,
      ol_w_id,
      ol_number,
      ol_i_id,
      ol_supply_w_id,
      ol_quantity,
      ol_amount,
      ol_delivery_d,
      ol_dist_info);
  };
  DECLARE_JSON_TYPE(OrderLine::Key);
  DECLARE_JSON_REQUIRED_FIELDS(
    OrderLine::Key,
    ol_o_id,
    ol_d_id,
    ol_w_id,
    ol_number);
  DECLARE_JSON_TYPE(OrderLine);
  DECLARE_JSON_REQUIRED_FIELDS(
    OrderLine,
    ol_o_id,
    ol_d_id,
    ol_w_id,
    ol_number,
    ol_i_id,
    ol_supply_w_id,
    ol_quantity,
    ol_amount,
    ol_delivery_d,
    ol_dist_info);

  struct NewOrder
  {
    static const int INITIAL_NUM_PER_DISTRICT = 900;

    struct Key
    {
      int32_t no_w_id;
      int32_t no_d_id;
      int32_t no_o_id;
      MSGPACK_DEFINE(no_w_id, no_d_id, no_o_id);
    };

    Key get_key()
    {
      return {no_w_id, no_d_id, no_o_id};
    }

    int32_t no_w_id;
    int32_t no_d_id;
    int32_t no_o_id;

    MSGPACK_DEFINE(no_w_id, no_d_id, no_o_id);
  };
  DECLARE_JSON_TYPE(NewOrder::Key);
  DECLARE_JSON_REQUIRED_FIELDS(NewOrder::Key, no_w_id, no_d_id, no_o_id);
  DECLARE_JSON_TYPE(NewOrder);
  DECLARE_JSON_REQUIRED_FIELDS(NewOrder, no_w_id, no_d_id, no_o_id);

  struct History
  {
    static const int MIN_DATA = 12;
    static const int MAX_DATA = 24;
    static constexpr float INITIAL_AMOUNT = 10.00f;

    struct Key
    {
      int32_t h_c_id;
      int32_t h_c_d_id;
      int32_t h_c_w_id;
      int32_t h_d_id;
      int32_t h_w_id;
      MSGPACK_DEFINE(h_c_id, h_c_d_id, h_c_w_id, h_d_id, h_w_id);
    };

    Key get_key()
    {
      return {h_c_id, h_c_d_id, h_c_w_id, h_d_id, h_w_id};
    }

    int32_t h_c_id;
    int32_t h_c_d_id;
    int32_t h_c_w_id;
    int32_t h_d_id;
    int32_t h_w_id;
    float h_amount;
    std::array<char, DATETIME_SIZE + 1> h_date;
    std::array<char, MAX_DATA + 1> h_data;

    MSGPACK_DEFINE(
      h_c_id, h_c_d_id, h_c_w_id, h_d_id, h_w_id, h_amount, h_date, h_data);
  };
  DECLARE_JSON_TYPE(History::Key);
  DECLARE_JSON_REQUIRED_FIELDS(
    History::Key,
    h_c_id,
    h_c_d_id,
    h_c_w_id,
    h_d_id,
    h_w_id);
  DECLARE_JSON_TYPE(History);
  DECLARE_JSON_REQUIRED_FIELDS(
    History,
    h_c_id,
    h_c_d_id,
    h_c_w_id,
    h_d_id,
    h_w_id,
    h_amount,
    h_date,
    h_data);

  // Data returned by the "order status" transaction.
  struct OrderStatusOutput
  {
    // From customer
    int32_t c_id; // unclear if this needs to be returned
    float c_balance;

    // From order
    int32_t o_id;
    int32_t o_carrier_id;

    struct OrderLineSubset
    {
      int32_t ol_i_id;
      int32_t ol_supply_w_id;
      int32_t ol_quantity;
      float ol_amount;
      std::array<char, DATETIME_SIZE + 1> ol_delivery_d;

      MSGPACK_DEFINE(
        ol_i_id, ol_supply_w_id, ol_quantity, ol_amount, ol_delivery_d);
    };

    std::vector<OrderLineSubset> lines;

    // From customer
    std::array<char, Customer::MAX_FIRST + 1> c_first;
    std::array<char, Customer::MIDDLE + 1> c_middle;
    std::array<char, Customer::MAX_LAST + 1> c_last;

    // From order
    std::array<char, DATETIME_SIZE + 1> o_entry_d;

    MSGPACK_DEFINE(
      c_id,
      c_balance,
      o_id,
      o_carrier_id,
      lines,
      c_first,
      c_middle,
      c_last,
      o_entry_d);
  };
  DECLARE_JSON_TYPE(OrderStatusOutput::OrderLineSubset);
  DECLARE_JSON_REQUIRED_FIELDS(
    OrderStatusOutput::OrderLineSubset,
    ol_i_id,
    ol_supply_w_id,
    ol_quantity,
    ol_amount,
    ol_delivery_d);
  DECLARE_JSON_TYPE(OrderStatusOutput);
  DECLARE_JSON_REQUIRED_FIELDS(
    OrderStatusOutput,
    c_id,
    c_balance,
    o_id,
    o_carrier_id,
    lines,
    c_first,
    c_middle,
    c_last,
    o_entry_d);

  struct NewOrderItem
  {
    int32_t i_id;
    int32_t ol_supply_w_id;
    int32_t ol_quantity;

    MSGPACK_DEFINE(i_id, ol_supply_w_id, ol_quantity);
  };
  DECLARE_JSON_TYPE(NewOrderItem);
  DECLARE_JSON_REQUIRED_FIELDS(NewOrderItem, i_id, ol_supply_w_id, ol_quantity);

  struct NewOrderOutput
  {
    // Zero initialize everything. This avoids copying uninitialized data around
    // when serializing/deserializing.
    NewOrderOutput() : w_tax(0), d_tax(0), o_id(0), c_discount(0), total(0)
    {
      std::fill(c_last.begin(), c_last.end(), 0);
      std::fill(c_credit.begin(), c_credit.end(), 0);
      std::fill(status.begin(), status.end(), 0);
    }

    float w_tax;
    float d_tax;

    // From district d_next_o_id
    int32_t o_id;

    float c_discount;

    // TODO: Client can compute this from other values.
    float total;

    struct ItemInfo
    {
      static const char BRAND = 'B';
      static const char GENERIC = 'G';

      int32_t s_quantity;
      float i_price;
      // TODO: Client can compute this from other values.
      float ol_amount;
      char brand_generic;
      std::array<char,Item::MAX_NAME + 1> i_name;

      MSGPACK_DEFINE(s_quantity, i_price, ol_amount, brand_generic, i_name);
    };

    std::vector<ItemInfo> items;
    std::array<char, Customer::MAX_LAST + 1> c_last;
    std::array<char, Customer::CREDIT + 1> c_credit;

    static const int MAX_STATUS = 25;
    static const char INVALID_ITEM_STATUS[];
    std::array<char,MAX_STATUS + 1> status;

    MSGPACK_DEFINE(
      w_tax, d_tax, o_id, c_discount, total, items, c_last, c_credit, status);
  };
  DECLARE_JSON_TYPE(NewOrderOutput::ItemInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    NewOrderOutput::ItemInfo,
    s_quantity,
    i_price,
    ol_amount,
    brand_generic,
    i_name);
  DECLARE_JSON_TYPE(NewOrderOutput);
  DECLARE_JSON_REQUIRED_FIELDS(
    NewOrderOutput,
    w_tax,
    d_tax,
    o_id,
    c_discount,
    total,
    items,
    c_last,
    c_credit,
    status);

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

    MSGPACK_DEFINE(
      w_street_1,
      w_street_2,
      w_city,
      w_state,
      w_zip,
      d_street_1,
      d_street_2,
      d_city,
      d_state,
      d_zip,
      c_credit_lim,
      c_discount,
      c_balance,
      c_first,
      c_middle,
      c_last,
      c_street_1,
      c_street_2,
      c_city,
      c_state,
      c_zip,
      c_phone,
      c_since,
      c_credit,
      c_data);
  };
  DECLARE_JSON_TYPE(PaymentOutput);
  DECLARE_JSON_REQUIRED_FIELDS(
    PaymentOutput,
    w_street_1,
    w_street_2,
    w_city,
    w_state,
    w_zip,
    d_street_1,
    d_street_2,
    d_city,
    d_state,
    d_zip,
    c_credit_lim,
    c_discount,
    c_balance,
    c_first,
    c_middle,
    c_last,
    c_street_1,
    c_street_2,
    c_city,
    c_state,
    c_zip,
    c_phone,
    c_since,
    c_credit,
    c_data);

  struct DeliveryOrderInfo
  {
    int32_t d_id;
    int32_t o_id;

    MSGPACK_DEFINE(d_id, o_id);
  };
  DECLARE_JSON_TYPE(DeliveryOrderInfo);
  DECLARE_JSON_REQUIRED_FIELDS(DeliveryOrderInfo, d_id, o_id);

  struct TpccTables
  {
    static kv::Map<Stock::Key, Stock> stocks;
    static kv::Map<Warehouse::Key, Warehouse> warehouses;
    static kv::Map<District::Key, District> districts;
    static kv::Map<History::Key, History> histories;
    static kv::Map<Customer::Key, Customer> customers;
    static kv::Map<Order::Key, Order> orders;
    static kv::Map<OrderLine::Key, OrderLine> order_lines;
    static kv::Map<NewOrder::Key, NewOrder> new_orders;
  };
}