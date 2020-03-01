// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <string>
#include <functional>
#include <msgpack.hpp>
#include "crypto/hash.h"

namespace ccfapp
{
namespace tpcc
{

    using WarehouseId = uint64_t;

    struct Warehouse
    {
        // Primary key: id
        std::string name;
        std::string street_1;
        std::string street_2;
        std::string city;
        std::string state;
        std::string zip;
        double tax;
        double ytd;

        MSGPACK_DEFINE(name, street_1, street_2, city, state, zip, tax, ytd);
    };

    struct DistrictId
    {
        uint64_t id;
        uint64_t w_id;

        bool operator==(const DistrictId& other) const
        {
            return id == other.id && w_id == other.w_id;
        }

        MSGPACK_DEFINE(id, w_id);
    };

    struct District
    {
        // Primary key: (w_id, id)
        std::string name;
        std::string street_1;
        std::string street_2;
        std::string city;
        std::string state;
        std::string zip;
        double tax;
        double ytd;
        uint64_t next_o_id;

        MSGPACK_DEFINE(name, street_1, street_2, city, state, zip, tax, ytd,
            next_o_id);
    };

    struct CustomerId
    {
        uint64_t id;
        uint64_t w_id;
        uint64_t d_id;

        bool operator==(const CustomerId& other) const
        {
            return id == other.id && w_id == other.w_id && d_id == other.d_id;
        }

        MSGPACK_DEFINE(id, w_id, d_id);
    };

    struct Customer
    {
        // Primary key: (w_id, d_id, id)
        std::string first;
        std::string middle;
        std::string last;        
        std::string street_1;
        std::string street_2;
        std::string city;
        std::string state;
        std::string zip;
        std::string phone;
        std::string since;
        std::string credit;
        double credit_lim;
        double discount;
        double balance;
        double ytd_payment;
        double payment_cnt;
        double delivery_cnt;
        std::string data;

        MSGPACK_DEFINE(first, middle, last, street_1, street_2, city, state, zip,
            phone, since, credit, credit_lim, discount, balance, ytd_payment,
            payment_cnt, delivery_cnt, data);
    };

    using HistoryId = uint64_t; 

    struct History
    {
        // Primary key: none
        uint64_t c_id;
        uint64_t c_d_id;
        uint64_t c_w_id;
        uint64_t d_id;
        uint64_t w_id;
        std::string date;
        double amount;
        std::string data;

        MSGPACK_DEFINE(c_id, c_d_id, c_w_id, d_id, w_id, date, amount, data);
    };

    struct NewOrderId 
    {
        uint64_t o_id;
        uint64_t w_id;
        uint64_t d_id;

        bool operator==(const NewOrderId& other) const
        {
            return o_id == other.o_id && w_id == other.w_id && d_id == other.d_id;
        }

        MSGPACK_DEFINE(o_id, w_id, d_id);
    };

    struct NewOrder
    {
        // Primary key: (w_id, d_id, o_id)
        uint8_t flag;

        MSGPACK_DEFINE(flag);
    };

    struct OrderId 
    {
        uint64_t id;
        uint64_t w_id;
        uint64_t d_id;

        bool operator==(const OrderId& other) const
        {
            return id == other.id && w_id == other.w_id && d_id == other.d_id;
        }

        MSGPACK_DEFINE(id, w_id, d_id);
    };

    struct Order
    {
        // Primary key: (w_id, d_id, id)
        uint64_t c_id;
        std::string entry_d;
        uint8_t carrier_id;
        uint64_t ol_cnt;
        uint8_t all_local;

        MSGPACK_DEFINE(c_id, entry_d, carrier_id, ol_cnt, all_local);
    };

    struct OrderLineId 
    {
        uint64_t o_id;
        uint64_t w_id;
        uint64_t d_id;
        uint64_t number;

        bool operator==(const OrderLineId& other) const
        {
            return o_id == other.o_id
                && w_id == other.w_id
                && d_id == other.d_id
                && number == other.number;
        }

        MSGPACK_DEFINE(o_id, w_id, d_id, number);
    };

    struct OrderLine
    {
        // Primary key: (w_id, d_id, o_id, number)
        uint64_t i_id;
        uint64_t supply_w_id;
        std::string delivery_d;
        uint8_t quantity;
        double amount;
        std::string dist_info;

        MSGPACK_DEFINE(i_id, supply_w_id, delivery_d, quantity,
            amount, dist_info);
    };

    using ItemId = uint64_t;

    struct Item
    {
        // Primary key: (id)
        uint64_t im_id;
        std::string name;
        double price;
        std::string data;

        MSGPACK_DEFINE(im_id, name, price, data);
    };

    struct StockId 
    {
        uint64_t w_id;
        uint64_t i_id;

        bool operator==(const StockId& other) const
        {
            return i_id == other.i_id && w_id == other.w_id;
        }

        MSGPACK_DEFINE(i_id, w_id);
    };

    struct Stock
    {
        // Primary key: (w_id, i_id)
        int16_t quantity;
        std::string dist_xx[10];
        // std::string dist_01;
        // std::string dist_02;
        // std::string dist_03;
        // std::string dist_04;
        // std::string dist_05;
        // std::string dist_06;
        // std::string dist_07;
        // std::string dist_08;
        // std::string dist_09;
        // std::string dist_10;
        uint32_t ytd;
        uint16_t order_cnt;
        uint16_t remote_cnt;
        std::string data;

        MSGPACK_DEFINE(quantity, dist_xx, ytd, order_cnt, remote_cnt, data);
        // MSGPACK_DEFINE(quantity, dist_01, dist_02, dist_03, dist_04, dist_05,
        //     dist_06, dist_07, dist_08, dist_09, dist_10, ytd, order_cnt,
        //     remote_cnt, data);
    };

    struct ItemOutputData
    {
        uint64_t ol_supply_w_id;
        uint64_t ol_i_id;
        uint64_t ol_quantity;
        uint64_t ol_amount;

        std::string i_name;
        double i_price;

        uint64_t s_quantity;

        char brand_generic;
    };

    struct OutputData
    {
        std::vector<ItemOutputData> item_data;

        uint64_t w_id;
        double w_tax;

        uint64_t d_id;
        double d_tax;

        uint64_t o_id;
        uint64_t o_ol_cnt;
        std::string o_entry_d;

        uint64_t c_id;
        std::string c_last;
        std::string c_credit;
        double c_discount;

        uint64_t total_amount;
        std::string status_msg;
    };

} // namespace tpcc
} // namespace ccfapp

namespace std
{
    template <> struct hash<ccfapp::tpcc::DistrictId> {
        std::size_t operator()(const ccfapp::tpcc::DistrictId& k) const {
            return hash<uint64_t>()(k.id) ^ (hash<uint64_t>()(k.w_id) << 1);
        }
    };

    template <> struct hash<ccfapp::tpcc::CustomerId> {
        std::size_t operator()(const ccfapp::tpcc::CustomerId& k) const {
            return ((hash<uint64_t>()(k.id)
                 ^ (hash<uint64_t>()(k.w_id) << 1)) >> 1)
                 ^ (hash<uint64_t>()(k.d_id) << 1);
        }
    };

    template <> struct hash<ccfapp::tpcc::NewOrderId> {
        std::size_t operator()(const ccfapp::tpcc::NewOrderId& k) const {
            return ((hash<uint64_t>()(k.o_id)
                 ^ (hash<uint64_t>()(k.w_id) << 1)) >> 1)
                 ^ (hash<uint64_t>()(k.d_id) << 1);
        }
    };

    template <> struct hash<ccfapp::tpcc::OrderId> {
        std::size_t operator()(const ccfapp::tpcc::OrderId& k) const {
            return ((hash<uint64_t>()(k.id)
                 ^ (hash<uint64_t>()(k.w_id) << 1)) >> 1)
                 ^ (hash<uint64_t>()(k.d_id) << 1);
        }
    };

    template <> struct hash<ccfapp::tpcc::OrderLineId> {
        std::size_t operator()(const ccfapp::tpcc::OrderLineId& k) const {
            return (((hash<uint64_t>()(k.number)
                 ^ (hash<uint64_t>()(k.o_id) << 1)) >> 1)
                 ^ (hash<uint64_t>()(k.w_id) << 1))
                 ^ (hash<uint64_t>()(k.d_id) << 1);
        }
    };

    template <> struct hash<ccfapp::tpcc::StockId> {
        std::size_t operator()(const ccfapp::tpcc::StockId& k) const {
            return hash<uint64_t>()(k.w_id) ^ (hash<uint64_t>()(k.i_id) << 1);
        }
    };
}