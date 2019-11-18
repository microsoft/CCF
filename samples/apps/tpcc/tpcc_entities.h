// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <string>
#include <msgpack.hpp>

namespace ccfapp
{
namespace tpcc
{

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
        std::string next_o_id;

        MSGPACK_DEFINE(name, street_1, street_2, city, state, zip, tax, ytd,
            next_o_id);
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

    struct History
    {
        // Primary key: none
        std::string c_id;
        std::string c_d_id;
        std::string c_w_id;
        std::string d_id;
        std::string w_id;
        std::string date;
        double amount;
        std::string data;

        MSGPACK_DEFINE(c_id, c_d_id, c_w_id, d_id, w_id, date, amount, data);
    };

    struct NewOrder
    {
        // Primary key: (w_id, d_id, o_id)

    };

    struct Order
    {
        // Primary key: (w_id, d_id, id)
        std::string c_id;
        std::string entry_d;
        std::string carrier_id;
        uint8_t ol_cnt;
        uint8_t all_local;  

        MSGPACK_DEFINE(c_id, entry_d, carrier_id, ol_cnt, all_local);
    };

    struct OrderLine
    {
        // Primary key: (w_id, d_id, o_id, id)
        std::string i_id;
        std::string supply_w_id;
        std::string delivery_id;
        std::string delivery_d;
        uint8_t quantity;
        double amount;
        std::string dist_info;

        MSGPACK_DEFINE(i_id, supply_w_id, delivery_id, delivery_d, quantity,
            amount, dist_info);
    };

    struct Item
    {
        // Primary key: (id)
        std::string im_id;
        std::string name;
        double price;
        std::string data;

        MSGPACK_DEFINE(im_id, name, price, data);
    };

    struct Stock
    {
        // Primary key: (w_id, i_id)
        int16_t quantity;
        std::string dist_01;
        std::string dist_02;
        std::string dist_03;
        std::string dist_04;
        std::string dist_05;
        std::string dist_06;
        std::string dist_07;
        std::string dist_08;
        std::string dist_09;
        std::string dist_10;
        uint32_t ytd;
        uint16_t order_cnt;
        uint16_t remote_cnt;
        std::string data;

        MSGPACK_DEFINE(quantity, dist_01, dist_02, dist_03, dist_04, dist_05,
            dist_06, dist_07, dist_08, dist_09, dist_10, ytd, order_cnt,
            remote_cnt, data);
    };

} // namespace tpcc
} // namespace ccf