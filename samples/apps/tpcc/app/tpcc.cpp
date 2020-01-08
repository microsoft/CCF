// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/appinterface.h"
#include "node/rpc/userfrontend.h"
#include "tpcc_entities.h"

using namespace ccf;

namespace ccfapp
{
namespace tpcc
{

  struct Procs {
    static constexpr auto TPCC_NEW_ORDER = "TPCC_new_order";
  };

  class Tpcc : public ccf::UserRpcFrontend
  {
  private:
    Store::Map<WarehouseId, Warehouse>& warehouses;
    Store::Map<DistrictId, District>& districts;
    Store::Map<CustomerId, Customer>& customers;
    Store::Map<HistoryId, History>& histories;
    Store::Map<NewOrderId, NewOrder>& neworders;
    Store::Map<OrderId, Order>& orders;
    Store::Map<OrderLineId, OrderLine>& orderlines;
    Store::Map<ItemId, Item>& items;
    Store::Map<StockId, Stock>& stocks;

  public:
    Tpcc(Store& tables) :
      UserRpcFrontend(tables),
      warehouses(tables.create<WarehouseId, Warehouse>("warehouses")),
      districts(tables.create<DistrictId, District>("districts")),
      customers(tables.create<CustomerId, Customer>("customers")),
      histories(tables.create<HistoryId, History>("histories")),
      neworders(tables.create<NewOrderId, NewOrder>("neworders")),
      orders(tables.create<OrderId, Order>("orders")),
      orderlines(tables.create<OrderLineId, OrderLine>("orderlines")),
      items(tables.create<ItemId, Item>("items")),
      stocks(tables.create<StockId, Stock>("stocks"))
    {
      auto newOrder = [this](Store::Tx& tx, const nlohmann::json& params) {
        uint64_t w_id = params["w_id"];
        uint64_t d_id = params["d_id"];
        uint64_t c_id = params["c_id"];
        std::string o_entry_d = params["o_entry_d"];
        std::vector<uint64_t> i_ids = params["i_ids"];
        std::vector<uint64_t> i_w_ids = params["i_w_ids"];
        std::vector<uint64_t> i_qtys = params["i_qtys"];

        // Output data defined as per TPCC 2.4.3.3
        OutputData output_data;
        output_data.w_id = w_id;
        output_data.d_id = d_id;
        output_data.c_id = c_id;
        output_data.o_entry_d = o_entry_d;

        // Get district information
        auto districts_view = tx.get_view(districts);

        DistrictId district_key = {d_id, w_id};
        auto d_result = districts_view->get(district_key);

        if (!d_result.has_value())
        {
          //TODO: Error
        }

        District d = d_result.value();
        double d_tax = d.tax;
        uint64_t d_next_o_id = d.next_o_id;

        output_data.d_tax = d_tax;
        output_data.o_id = d_next_o_id;

        // Update the district's next order number
        d.next_o_id += 1;
        districts_view->put(district_key, d);
      
        // Get warehouse information
        auto warehouses_view = tx.get_view(warehouses);

        WarehouseId warehouse_key = w_id;
        auto w_result = warehouses_view->get(warehouse_key);
        
        if (!w_result.has_value())
        {
          //TODO: Error
        }

        Warehouse w = w_result.value();
        double w_tax = w.tax;

        output_data.w_tax = w_tax;

        // Get customer information
        auto customers_view = tx.get_view(customers);

        CustomerId customer_key = {c_id, w_id, d_id};
        auto c_result = customers_view->get(customer_key);

        if (!c_result.has_value())
        {
          //TODO: Error
        }

        Customer c = c_result.value();
        double c_discount = c.discount;
        std::string c_last = c.last;
        std::string c_credit = c.credit;

        output_data.c_last = c_last;
        output_data.c_credit = c_credit;
        output_data.c_discount = c_discount;

        // Insert NewOrder entry
        auto neworders_view = tx.get_view(neworders);

        NewOrderId neworder_key = {d_next_o_id, w_id, d_id};
        NewOrder no = {0};
        neworders_view->put(neworder_key, no);

        // Insert Order entry
        auto orders_view = tx.get_view(orders);

        uint8_t all_local = 0; //TODO: set this appropriately
        uint64_t ol_cnt = i_ids.size();

        output_data.o_ol_cnt = ol_cnt;

        OrderId order_key = {d_next_o_id, w_id, d_id};
        Order order = {
          c_id,
          o_entry_d,
          0, // carrier_id unused for benchmark purposes
          ol_cnt,
          all_local
        };

        // TODO: order is inserted at the end, check this

        // Insert Order Line and Stock Information
        auto items_view = tx.get_view(items);
        auto stocks_view = tx.get_view(stocks);
        auto orderlines_view = tx.get_view(orderlines);

        uint64_t total = 0;

        std::vector<ItemOutputData> item_output_data;
        item_output_data.reserve(ol_cnt);

        for (size_t i = 1; i <= ol_cnt; i++)
        {
          uint64_t i_id = i_ids.at(i);
          uint64_t i_w_id = i_w_ids.at(i);
          uint64_t ol_quantity = i_qtys.at(i);

          // Stores required output data for item as per TPCC 2.4.3.3
          ItemOutputData item_data;
          item_data.ol_supply_w_id = i_w_id;
          item_data.ol_i_id = i_id;
          item_data.ol_quantity = ol_quantity;

          // Find the ITEM
          auto i_result = items_view->get(i_id);

          if (!i_result.has_value())
          {
            // 'not-found' signal, item was not found in store
            // TODO: rollback transaction
          }

          Item item = i_result.value();
          double i_price = item.price;
          std::string i_name = item.name;
          std::string i_data = item.data;

          item_data.i_name = i_name;
          item_data.i_price = i_price;

          // Find the STOCK
          StockId stock_key = {i_w_id, i_id};
          auto s_result = stocks_view->get(stock_key);

          if (!s_result.has_value())
          {
            //TODO: Error
          }

          Stock stock = s_result.value();

          // Update stock information
          if (stock.quantity >= ol_quantity + 10)
          {
            stock.quantity -= ol_quantity;
          }
          else
          {
            stock.quantity = stock.quantity - ol_quantity + 91;
          }

          stock.ytd += ol_quantity;
          stock.order_cnt += 1;

          if (i_w_id != w_id)
          {
            stock.remote_cnt += 1;
          }

          stocks_view->put(stock_key, stock);
          item_data.s_quantity = stock.quantity;

          // Check the data for the 'brand-generic' field
          char brand_generic;
          if (i_data.find("ORIGINAL") != std::string::npos 
              && stock.data.find("ORIGINAL") != std::string::npos)
          {
            brand_generic = 'B';
          }
          else
          {
            brand_generic = 'G';
          }

          item_data.brand_generic = brand_generic;

          // Insert the OrderLine entry
          uint64_t ol_amount = ol_quantity * i_price;

          item_data.ol_amount = ol_amount;
          total += ol_amount;

          OrderLineId orderline_key = {d_next_o_id, w_id, d_id, i};
          OrderLine orderline = {
            i_id,
            i_w_id,
            "",
            (uint8_t) stock.quantity,
            (double) ol_amount,
            stock.dist_xx[d_id]
          };

          orderlines_view->put(orderline_key, orderline);
          item_output_data.push_back(item_data);
        }

        total *= (1 - c_discount) * (1 + w_tax + d_tax);

        orders_view->put(order_key, order);

        output_data.item_data = item_output_data;
        output_data.total_amount = total;
        output_data.status_msg = "Success";

        // TODO: should OutputData be printed as per TPCC spec?

        return jsonrpc::success(true);
      };

      install(Procs::TPCC_NEW_ORDER, newOrder, Write);
    }
  };

  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    NetworkTables& nwt, AbstractNotifier& notifier)
  {
    return std::make_shared<Tpcc>(*nwt.tables);
  }

} // namespace tpcc
} // namespace ccfapp
