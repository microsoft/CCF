// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/service/node_info_network.h"
#include "clients/perf/perf_client.h"
#include "clients/rpc_tls_client.h"
#include "crypto/openssl/hash.h"
#include "ds/files.h"
#include "handle_arguments.h"
#include "parquet_data.h"

#include <CLI11/CLI11.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <arrow/array/array_binary.h>
#include <arrow/builder.h>
#include <arrow/filesystem/localfs.h>
#include <arrow/io/file.h>
#include <arrow/table.h>
#include <arrow/util/config.h>
#include <parquet/arrow/reader.h>
#include <parquet/arrow/writer.h>
#pragma GCC diagnostic pop
#include <signal.h>
#include <time.h>
#include <utility>

using namespace std;
using namespace client;

ccf::crypto::Pem key = {};
std::string key_id = "Invalid";
std::shared_ptr<::tls::Cert> tls_cert = nullptr;

static int64_t get_realtime_us()

{
  timespec timestamp;
  clock_gettime(CLOCK_REALTIME, &timestamp);
  return timestamp.tv_sec * 1'000'000 + timestamp.tv_nsec / 1000;
}

class ResponseData
{
private:
  arrow::TimestampBuilder response_time_builder;
  arrow::NumericBuilder<arrow::UInt64Type> response_status_builder;
  arrow::StringBuilder response_headers_builder;
  arrow::BinaryBuilder response_body_builder;

public:
  ResponseData() :
    response_time_builder(
      arrow::timestamp(arrow::TimeUnit::MICRO), arrow::default_memory_pool())
  {}

  void reserve(size_t size)
  {
    PARQUET_THROW_NOT_OK(response_time_builder.Reserve(size));
    PARQUET_THROW_NOT_OK(response_status_builder.Reserve(size));
    PARQUET_THROW_NOT_OK(response_headers_builder.Reserve(size));
    PARQUET_THROW_NOT_OK(response_body_builder.Reserve(size));
  }

  void append(
    client::HttpRpcTlsClient::Response&& response, int64_t response_time)
  {
    PARQUET_THROW_NOT_OK(response_time_builder.Append(response_time));
    PARQUET_THROW_NOT_OK(response_status_builder.Append(response.status));

    std::string concat_headers;
    for (const auto& [name, value] : response.headers)
    {
      if (!concat_headers.empty())
      {
        concat_headers += "\n";
      }
      concat_headers += fmt::format("{}: {}", name, value);
    }
    PARQUET_THROW_NOT_OK(response_headers_builder.Append(concat_headers));
    PARQUET_THROW_NOT_OK(
      response_body_builder.Append(response.body.data(), response.body.size()));
  }

  int64_t size() const
  {
    return response_time_builder.length();
  }

  std::shared_ptr<arrow::Array> finish_response_times()
  {
    return response_time_builder.Finish().ValueOrDie();
  }

  std::shared_ptr<arrow::Array> finish_response_statuses()
  {
    return response_status_builder.Finish().ValueOrDie();
  }

  std::shared_ptr<arrow::Array> finish_response_headers()
  {
    return response_headers_builder.Finish().ValueOrDie();
  }

  std::shared_ptr<arrow::Array> finish_response_bodies()
  {
    return response_body_builder.Finish().ValueOrDie();
  }
};

void read_parquet_file(string generator_filepath, ParquetData& data_handler)
{
  arrow::Status st;
  arrow::MemoryPool* pool = arrow::default_memory_pool();
  arrow::fs::LocalFileSystem file_system;
  std::shared_ptr<arrow::io::RandomAccessFile> input =
    file_system.OpenInputFile(generator_filepath).ValueOrDie();

  // Open Parquet file reader
#if ARROW_VERSION_MAJOR >= 19
  auto arrow_reader_result = parquet::arrow::OpenFile(input, pool);
  if (!arrow_reader_result.ok())
  {
    LOG_FAIL_FMT(
      "Couldn't find generator file ({}): {}",
      generator_filepath,
      arrow_reader_result.status().ToString());
    exit(1);
  }
  else
  {
    LOG_INFO_FMT("Found generator file");
  }
  auto arrow_reader = std::move(arrow_reader_result).ValueOrDie();
#else
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
#endif

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

  data_handler.ids =
    std::dynamic_pointer_cast<arrow::StringArray>(message_id_column->chunk(0));
  if (data_handler.ids == nullptr)
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

  data_handler.requests =
    std::dynamic_pointer_cast<arrow::BinaryArray>(request_column->chunk(0));
  if (data_handler.requests == nullptr)
  {
    LOG_FAIL_FMT(
      "The request column of input file could not be read as binary array");
    exit(1);
  }

  if (data_handler.ids->length() != data_handler.requests->length())
  {
    LOG_FAIL_FMT(
      "Generator file contains {} message IDs but {} requests",
      data_handler.ids->length(),
      data_handler.requests->length());
    exit(1);
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

void store_parquet_results(
  const ArgumentParser& args,
  const ParquetData& data_handler,
  ResponseData& response_data)
{
  LOG_INFO_FMT("Start storing results");

  auto us_timestamp_type = arrow::timestamp(arrow::TimeUnit::MICRO);

  // Write Send Parquet
  {
    arrow::TimestampBuilder send_time_builder(
      us_timestamp_type, arrow::default_memory_pool());
    PARQUET_THROW_NOT_OK(
      send_time_builder.AppendValues(data_handler.send_time));

    auto table = arrow::Table::Make(
      arrow::schema(
        {arrow::field("messageID", arrow::utf8()),
         arrow::field("sendTime", us_timestamp_type)}),
      {data_handler.ids, send_time_builder.Finish().ValueOrDie()});

    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    PARQUET_ASSIGN_OR_THROW(
      outfile, arrow::io::FileOutputStream::Open(args.send_filepath));
    PARQUET_THROW_NOT_OK(
      parquet::arrow::WriteTable(
        *table, arrow::default_memory_pool(), outfile));
  }

  // Write Response Parquet
  {
    auto table = arrow::Table::Make(
      arrow::schema({
        arrow::field("messageID", arrow::utf8()),
        arrow::field("receiveTime", us_timestamp_type),
        arrow::field("responseStatus", arrow::uint64()),
        arrow::field("responseHeaders", arrow::utf8()),
        arrow::field("rawResponse", arrow::binary()),
      }),
      {data_handler.ids,
       response_data.finish_response_times(),
       response_data.finish_response_statuses(),
       response_data.finish_response_headers(),
       response_data.finish_response_bodies()});

    std::shared_ptr<arrow::io::FileOutputStream> outfile;
    PARQUET_ASSIGN_OR_THROW(
      outfile, arrow::io::FileOutputStream::Open(args.response_filepath));
    PARQUET_THROW_NOT_OK(
      parquet::arrow::WriteTable(
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

  const auto requests_size = static_cast<size_t>(data_handler.ids->length());
  data_handler.send_time.resize(requests_size);
  ResponseData response_data;
  response_data.reserve(requests_size);

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
        data_handler.send_time[ridx] = get_realtime_us();
        const auto request = data_handler.requests->Value(ridx);
        connection->write(
          {reinterpret_cast<const uint8_t*>(request.data()), request.size()});
        if (
          connection->bytes_available() or
          (args.max_inflight_requests >= 0 &&
           ridx - read_reqs >= static_cast<size_t>(args.max_inflight_requests)))
        {
          response_data.append(connection->read_response(), get_realtime_us());
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
        response_data.append(connection->read_response(), get_realtime_us());
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

  if (response_data.size() != static_cast<int64_t>(requests_size))
  {
    LOG_FAIL_FMT(
      "Received {} responses for {} requests",
      response_data.size(),
      requests_size);
    return 1;
  }

  store_parquet_results(args, data_handler, response_data);

  return 0;
}
