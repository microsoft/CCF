// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/service/node_info_network.h"
#include "clients/perf/perf_client.h"
#include "clients/rpc_tls_client.h"
#include "ds/files.h"
#include "handle_arguments.h"
#include "parquet_data.h"

#include <CLI11/CLI11.hpp>
#include <arrow/array/array_binary.h>
#include <arrow/builder.h>
#include <arrow/filesystem/localfs.h>
#include <arrow/io/file.h>
#include <arrow/table.h>
#include <parquet/arrow/reader.h>
#include <parquet/arrow/writer.h>
#include <sys/time.h>

using namespace std;
using namespace client;

crypto::Pem key = {};
std::string key_id = "Invalid";
std::shared_ptr<tls::Cert> tls_cert = nullptr;

void read_parquet_file(string generator_filepath, ParquetData& data_handler)
{
  arrow::Status st;
  arrow::MemoryPool* pool = arrow::default_memory_pool();
  arrow::fs::LocalFileSystem file_system;
  std::shared_ptr<arrow::io::RandomAccessFile> input =
    file_system.OpenInputFile(generator_filepath).ValueOrDie();

  // Open Parquet file reader
  std::unique_ptr<parquet::arrow::FileReader> arrow_reader;
  st = parquet::arrow::OpenFile(input, pool, &arrow_reader);
  if (!st.ok())
  {
    LOG_FAIL_FMT("Couldn't find generator file");
    exit(1);
  }
  else
  {
    LOG_INFO_FMT("Found generator file");
  }

  // Read entire file as a single Arrow table
  std::shared_ptr<arrow::Table> table = nullptr;
  st = arrow_reader->ReadTable(&table);
  if (!st.ok() || table == nullptr)
  {
    LOG_FAIL_FMT("Couldn't open generator file: {}", st.ToString());
    exit(1);
  }
  else
  {
    LOG_INFO_FMT("Opened generator file");
  }

  const auto& schema = table->schema();

  std::vector<std::string> column_names = {"messageID", "request"};

  st = schema->CanReferenceFieldsByNames(column_names);
  if (!st.ok())
  {
    LOG_FAIL_FMT(
      "Input file does not contain unambiguous field names - cannot lookup "
      "desired columns: {}",
      st.ToString());
    exit(1);
  }

  const auto message_id_idx = schema->GetFieldIndex("messageID");
  if (message_id_idx == -1)
  {
    LOG_FAIL_FMT("No messageID field found in file");
    exit(1);
  }

  std::shared_ptr<::arrow::ChunkedArray> message_id_column =
    table->column(message_id_idx);
  if (message_id_column->num_chunks() != 1)
  {
    LOG_FAIL_FMT(
      "Expected a single chunk, found {}", message_id_column->num_chunks());
    exit(1);
  }

  auto message_id_values =
    std::dynamic_pointer_cast<arrow::StringArray>(message_id_column->chunk(0));
  if (message_id_values == nullptr)
  {
    LOG_FAIL_FMT(
      "The messageID column of input file could not be read as string array");
    exit(1);
  }

  const auto request_idx = schema->GetFieldIndex("request");
  if (request_idx == -1)
  {
    LOG_FAIL_FMT("No request field found in file");
    exit(1);
  }

  std::shared_ptr<::arrow::ChunkedArray> request_column =
    table->column(request_idx);
  if (request_column->num_chunks() != 1)
  {
    LOG_FAIL_FMT(
      "Expected a single chunk, found {}", request_column->num_chunks());
    exit(1);
  }

  auto request_values =
    std::dynamic_pointer_cast<arrow::BinaryArray>(request_column->chunk(0));
  if (request_values == nullptr)
  {
    LOG_FAIL_FMT(
      "The request column of input file could not be read as binary array");
    exit(1);
  }

  for (int row = 0; row < table->num_rows(); row++)
  {
    data_handler.ids.push_back(message_id_values->GetString(row));
    const auto request = request_values->Value(row);
    data_handler.request.push_back({request.begin(), request.end()});
  }
}

std::shared_ptr<RpcTlsClient> create_connection(
  std::vector<string> certificates, std::string server_address)
{
  // Create a cert if this is our first rpc_connection
  const bool is_first_time = tls_cert == nullptr;

  if (is_first_time)
  {
    const auto raw_cert = files::slurp(certificates[0].c_str());
    const auto raw_key = files::slurp(certificates[1].c_str());
    const auto ca = files::slurp_string(certificates[2].c_str());

    key = crypto::Pem(raw_key);

    const crypto::Pem cert_pem(raw_cert);
    auto cert_der = crypto::cert_pem_to_der(cert_pem);
    key_id = crypto::Sha256Hash(cert_der).hex_str();

    tls_cert =
      std::make_shared<tls::Cert>(std::make_shared<tls::CA>(ca), cert_pem, key);
  }

  const auto [host, port] = ccf::split_net_address(server_address);
  auto conn =
    std::make_shared<RpcTlsClient>(host, port, nullptr, tls_cert, key_id);

  // Report ciphersuite of first client (assume it is the same for each)
  if (is_first_time)
  {
    LOG_DEBUG_FMT(
      "Connected to server via TLS ({})", conn->get_ciphersuite_name());
  }

  return conn;
}

void store_parquet_results(ArgumentParser args, ParquetData data_handler)
{
  LOG_INFO_FMT("Start storing results");

  // Write Send Parquet
  {
    arrow::StringBuilder message_id_builder;
    PARQUET_THROW_NOT_OK(message_id_builder.AppendValues(data_handler.ids));

    arrow::NumericBuilder<arrow::DoubleType> send_time_builder;
    PARQUET_THROW_NOT_OK(
      send_time_builder.AppendValues(data_handler.send_time));

    auto table = arrow::Table::Make(
      arrow::schema(
        {arrow::field("messageID", arrow::utf8()),
         arrow::field("sendTime", arrow::float64())}),
      {message_id_builder.Finish().ValueOrDie(),
       send_time_builder.Finish().ValueOrDie()});

    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    PARQUET_ASSIGN_OR_THROW(
      outfile, arrow::io::FileOutputStream::Open(args.send_filepath));
    PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(
      *table, arrow::default_memory_pool(), outfile, 1));
  }

  // Write Response Parquet
  {
    arrow::StringBuilder message_id_builder;
    PARQUET_THROW_NOT_OK(message_id_builder.AppendValues(data_handler.ids));

    arrow::NumericBuilder<arrow::DoubleType> receive_time_builder;
    PARQUET_THROW_NOT_OK(
      receive_time_builder.AppendValues(data_handler.response_time));

    arrow::BinaryBuilder raw_response_builder;
    for (auto& raw_response : data_handler.raw_response)
    {
      PARQUET_THROW_NOT_OK(
        raw_response_builder.Append(raw_response.data(), raw_response.size()));
    }

    auto table = arrow::Table::Make(
      arrow::schema({
        arrow::field("messageID", arrow::utf8()),
        arrow::field("receiveTime", arrow::float64()),
        arrow::field("rawResponse", arrow::binary()),
      }),
      {message_id_builder.Finish().ValueOrDie(),
       receive_time_builder.Finish().ValueOrDie(),
       raw_response_builder.Finish().ValueOrDie()});

    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    PARQUET_ASSIGN_OR_THROW(
      outfile, arrow::io::FileOutputStream::Open(args.response_filepath));
    PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(
      *table, arrow::default_memory_pool(), outfile, 1));
  }

  LOG_INFO_FMT("Finished storing results");
}

int main(int argc, char** argv)
{
  logger::config::default_init();
  CLI::App cli_app{"Perf Tool"};
  ArgumentParser args("Perf Tool", cli_app);
  CLI11_PARSE(cli_app, argc, argv);

  ParquetData data_handler;
  std::vector<string> certificates = {args.cert, args.key, args.rootCa};

  read_parquet_file(args.generator_filepath, data_handler);
  std::string server_address = args.server_address;

  // Keep only the host and port removing any https:// characters
  std::string separator = "//";
  auto exists_index = server_address.find(separator);
  if (exists_index != std::string::npos)
  {
    server_address = server_address.substr(exists_index + separator.length());
  }

  auto requests_size = data_handler.ids.size();

  std::vector<timeval> start(requests_size);
  std::vector<timeval> end(requests_size);

  // Store responses until they are processed to be written in parquet
  std::vector<std::vector<uint8_t>> resp_text(data_handler.ids.size());

  LOG_INFO_FMT("Start Request Submission");

  if (args.max_inflight_requests == 0)
  {
    // Request by Request under one connection
    auto connection = create_connection(certificates, server_address);
    for (size_t req = 0; req < requests_size; req++)
    {
      gettimeofday(&start[req], NULL);
      auto request = data_handler.request[req];
      connection->write({request.data(), request.size()});
      resp_text[req] = connection->read_raw_response();
      gettimeofday(&end[req], NULL);
    }
  }
  else
  {
    // Pipeline
    int read_reqs = 0; // use this to block writes
    auto connection = create_connection(certificates, server_address);

    if (args.max_inflight_requests < 0)
    {
      // Unlimited outstanding orders
      for (size_t req = 0; req < requests_size; req++)
      {
        gettimeofday(&start[req], NULL);
        auto request = data_handler.request[req];
        connection->write({request.data(), request.size()});
        if (connection->bytes_available())
        {
          resp_text[read_reqs] = connection->read_raw_response();
          gettimeofday(&end[read_reqs], NULL);
          read_reqs++;
        }
      }
    }
    else
    {
      // Capped outstanding orders
      for (size_t req = 0; req < requests_size; req++)
      {
        gettimeofday(&start[req], NULL);
        auto request = data_handler.request[req];
        connection->write({request.data(), request.size()});
        if (
          connection->bytes_available() or
          req - read_reqs >= args.max_inflight_requests)
        {
          resp_text[read_reqs] = connection->read_raw_response();
          gettimeofday(&end[read_reqs], NULL);
          read_reqs++;
        }
      }
    }

    // Read remaining responses
    while (read_reqs < requests_size)
    {
      resp_text[read_reqs] = connection->read_raw_response();
      gettimeofday(&end[read_reqs], NULL);
      read_reqs++;
    }
  }

  LOG_INFO_FMT("Finished Request Submission");

  for (size_t req = 0; req < requests_size; req++)
  {
    data_handler.raw_response.push_back(resp_text[req]);
    double send_time = start[req].tv_sec + start[req].tv_usec / 1000000.0;
    double response_time = end[req].tv_sec + end[req].tv_usec / 1000000.0;
    data_handler.send_time.push_back(send_time);
    data_handler.response_time.push_back(response_time);
  }

  store_parquet_results(args, data_handler);
}
