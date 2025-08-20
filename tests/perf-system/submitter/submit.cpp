// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/service/node_info_network.h"
#include "ccf/crypto/openssl_init.h"
#include "clients/perf/perf_client.h"
#include "clients/rpc_tls_client.h"
#include "crypto/openssl/hash.h"
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
#include <signal.h>
#include <time.h>

using namespace std;
using namespace client;

ccf::crypto::Pem key = {};
std::string key_id = "Invalid";
std::shared_ptr<::tls::Cert> tls_cert = nullptr;

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
    LOG_FAIL_FMT(
      "Couldn't find generator file ({}): {}",
      generator_filepath,
      st.ToString());
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
    LOG_FAIL_FMT(
      "Couldn't open generator file ({}): {}",
      generator_filepath,
      st.ToString());
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

  for (int64_t row = 0; row < table->num_rows(); row++)
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

    key = ccf::crypto::Pem(raw_key);

    const ccf::crypto::Pem cert_pem(raw_cert);
    auto cert_der = ccf::crypto::cert_pem_to_der(cert_pem);
    key_id = ccf::crypto::Sha256Hash(cert_der).hex_str();

    tls_cert = std::make_shared<::tls::Cert>(
      std::make_shared<::tls::CA>(ca), cert_pem, key);
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

  auto us_timestamp_type = arrow::timestamp(arrow::TimeUnit::MICRO);

  // Write Send Parquet
  {
    arrow::StringBuilder message_id_builder;
    PARQUET_THROW_NOT_OK(message_id_builder.AppendValues(data_handler.ids));

    arrow::TimestampBuilder send_time_builder(
      us_timestamp_type, arrow::default_memory_pool());
    PARQUET_THROW_NOT_OK(
      send_time_builder.AppendValues(data_handler.send_time));

    auto table = arrow::Table::Make(
      arrow::schema(
        {arrow::field("messageID", arrow::utf8()),
         arrow::field("sendTime", us_timestamp_type)}),
      {message_id_builder.Finish().ValueOrDie(),
       send_time_builder.Finish().ValueOrDie()});

    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    PARQUET_ASSIGN_OR_THROW(
      outfile, arrow::io::FileOutputStream::Open(args.send_filepath));
    PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(
      *table, arrow::default_memory_pool(), outfile));
  }

  // Write Response Parquet
  {
    arrow::StringBuilder message_id_builder;
    PARQUET_THROW_NOT_OK(message_id_builder.AppendValues(data_handler.ids));

    arrow::TimestampBuilder receive_time_builder(
      us_timestamp_type, arrow::default_memory_pool());
    PARQUET_THROW_NOT_OK(
      receive_time_builder.AppendValues(data_handler.response_time));

    arrow::NumericBuilder<arrow::UInt64Type> response_status_builder;
    for (const auto& response_status : data_handler.response_status_code)
    {
      PARQUET_THROW_NOT_OK(response_status_builder.Append(response_status));
    }

    arrow::StringBuilder response_headers_builder;
    for (const auto& response_headers : data_handler.response_headers)
    {
      PARQUET_THROW_NOT_OK(response_headers_builder.Append(response_headers));
    }

    arrow::BinaryBuilder response_body_builder;
    for (auto& response_body : data_handler.response_body)
    {
      PARQUET_THROW_NOT_OK(response_body_builder.Append(
        response_body.data(), response_body.size()));
    }

    auto table = arrow::Table::Make(
      arrow::schema({
        arrow::field("messageID", arrow::utf8()),
        arrow::field("receiveTime", us_timestamp_type),
        arrow::field("responseStatus", arrow::uint64()),
        arrow::field("responseHeaders", arrow::utf8()),
        arrow::field("rawResponse", arrow::binary()),
      }),
      {message_id_builder.Finish().ValueOrDie(),
       receive_time_builder.Finish().ValueOrDie(),
       response_status_builder.Finish().ValueOrDie(),
       response_headers_builder.Finish().ValueOrDie(),
       response_body_builder.Finish().ValueOrDie()});

    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    PARQUET_ASSIGN_OR_THROW(
      outfile, arrow::io::FileOutputStream::Open(args.response_filepath));
    PARQUET_THROW_NOT_OK(parquet::arrow::WriteTable(
      *table, arrow::default_memory_pool(), outfile));
  }

  LOG_INFO_FMT("Finished storing results");
}

int main(int argc, char** argv)
{
  // Ignore SIGPIPE as it can be raised by write to a socket
  signal(SIGPIPE, SIG_IGN);

  ccf::logger::config::default_init();
  ccf::logger::config::level() = ccf::LoggerLevel::INFO;
  ccf::crypto::openssl_sha256_init();
  CLI::App cli_app{"Perf Tool"};
  ArgumentParser args("Perf Tool", cli_app);
  CLI11_PARSE(cli_app, argc, argv);

  std::vector<std::string> args_str(argv, argv + argc);
  LOG_INFO_FMT("Running {}", fmt::join(args_str, " "));

  ParquetData data_handler;
  std::vector<string> certificates = {args.cert, args.key, args.rootCa};

  read_parquet_file(args.generator_filepath, data_handler);
  std::string server_address = args.server_address;
  std::string failover_server_address = args.failover_server_address;
  if (failover_server_address.empty())
  {
    failover_server_address = server_address;
  }

  // Write PID to disk
  files::dump(fmt::format("{}", ::getpid()), args.pid_file_path);

  auto requests_size = data_handler.ids.size();

  std::vector<timespec> start(requests_size);
  std::vector<timespec> end(requests_size);

  // Store responses until they are processed to be written in parquet
  std::vector<client::HttpRpcTlsClient::Response> responses(
    data_handler.ids.size());

  LOG_INFO_FMT("Start Request Submission");

  constexpr size_t retry_max = 5;
  size_t retry_count = 0;
  size_t read_reqs = 0;

  LOG_INFO_FMT("Connecting to {}", server_address);
  auto connection = create_connection(certificates, server_address);
  connection->set_tcp_nodelay(true);
  LOG_INFO_FMT("Connected to {}", server_address);

  while (retry_count < retry_max)
  {
    try
    {
      for (size_t ridx = read_reqs; ridx < requests_size; ridx++)
      {
        clock_gettime(CLOCK_REALTIME, &start[ridx]);
        auto request = data_handler.request[ridx];
        connection->write({request.data(), request.size()});
        if (
          connection->bytes_available() or
          ridx - read_reqs >= args.max_inflight_requests)
        {
          responses[read_reqs] = connection->read_response();
          clock_gettime(CLOCK_REALTIME, &end[read_reqs]);
          read_reqs++;
        }
        if (ridx % 20000 == 0)
        {
          LOG_INFO_FMT("Sent {} requests", ridx);
        }
      }
      // Read remaining responses
      while (read_reqs < requests_size)
      {
        responses[read_reqs] = connection->read_response();
        clock_gettime(CLOCK_REALTIME, &end[read_reqs]);
        read_reqs++;
      }
      connection.reset();
      break;
    }
    catch (std::logic_error& e)
    {
      LOG_FAIL_FMT(
        "Sending interrupted: {}, attempting reconnection to {}",
        e.what(),
        failover_server_address);
      connection = create_connection(certificates, failover_server_address);
      connection->set_tcp_nodelay(true);
      LOG_INFO_FMT("Reconnected to {}", failover_server_address);
      retry_count++;
    }
  }

  LOG_INFO_FMT("Finished Request Submission");

  for (size_t req = 0; req < requests_size; req++)
  {
    auto& response = responses[req];
    data_handler.response_status_code.push_back(response.status);
    std::string concat_headers;
    for (const auto& [k, v] : response.headers)
    {
      if (!concat_headers.empty())
      {
        concat_headers += "\n";
      }
      concat_headers += fmt::format("{}: {}", k, v);
    }
    data_handler.response_headers.push_back(concat_headers);
    data_handler.response_body.push_back(std::move(response.body));

    size_t send_time_us =
      start[req].tv_sec * 1'000'000 + start[req].tv_nsec / 1000;
    size_t response_time_us =
      end[req].tv_sec * 1'000'000 + end[req].tv_nsec / 1000;
    data_handler.send_time.push_back(send_time_us);
    data_handler.response_time.push_back(response_time_us);
  }

  store_parquet_results(args, data_handler);
  ccf::crypto::openssl_sha256_shutdown();

  return 0;
}
