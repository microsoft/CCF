// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/service/node_info_network.h"
#include "clients/perf/perf_client.h"
#include "clients/rpc_tls_client.h"
#include "ds/files.h"
#include "handle_arguments.hpp"
#include "parquet_data.hpp"

#include <CLI11/CLI11.hpp>
#include <arrow/array/array_binary.h>
#include <arrow/filesystem/localfs.h>
#include <arrow/io/file.h>
#include <parquet/arrow/reader.h>
#include <parquet/stream_writer.h>

using namespace std;
using namespace client;

crypto::Pem key = {};
std::string key_id = "Invalid";
std::shared_ptr<tls::Cert> tls_cert = nullptr;

void readParquetFile(string generator_filepath, ParquetData& data_handler)
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
    LOG_INFO_FMT("Couldn't found generator file");
  }
  else
  {
    LOG_INFO_FMT("Found generator file");
  }

  // Read entire file as a single Arrow table
  auto selected_columns = {0, 1};
  std::shared_ptr<arrow::Table> table;
  st = arrow_reader->ReadTable(selected_columns, &table);
  if (!st.ok())
  {
    LOG_INFO_FMT("Couldn't open generator file");
  }
  else
  {
    LOG_INFO_FMT("Opened generator file");
  }

  std::shared_ptr<::arrow::ChunkedArray> column;

  ::arrow::Status column1Status = arrow_reader->ReadColumn(1, &column);
  std::shared_ptr<arrow::StringArray> col1Vals =
    std::dynamic_pointer_cast<arrow::StringArray>(column->chunk(
      0)); // ASSIGN there is only one chunk with col->num_chunks();

  ::arrow::Status column2Status = arrow_reader->ReadColumn(2, &column);
  std::shared_ptr<arrow::StringArray> col2Vals =
    std::dynamic_pointer_cast<arrow::StringArray>(column->chunk(
      0)); // ASSIGN there is only one chunk with col->num_chunks();
  for (int row = 0; row < col1Vals->length(); row++)
  {
    data_handler.IDS.push_back(col1Vals->GetString(row));
    data_handler.REQUEST.push_back(col2Vals->GetString(row));
  }
}

parquet::StreamWriter initParquetColumns(
  std::string filepath,
  ParquetData& data_handler,
  std::vector<
    std::tuple<std::string, parquet::Type::type, parquet::ConvertedType::type>>
    columns)
{
  std::shared_ptr<arrow::io::FileOutputStream> outfile;

  PARQUET_ASSIGN_OR_THROW(outfile, arrow::io::FileOutputStream::Open(filepath));

  parquet::WriterProperties::Builder builder;

  parquet::schema::NodeVector fields;

  for (auto const& col : columns)
  {
    fields.push_back(parquet::schema::PrimitiveNode::Make(
      std::get<0>(col),
      parquet::Repetition::REQUIRED,
      std::get<1>(col),
      std::get<2>(col)));
  }

  std::shared_ptr<parquet::schema::GroupNode> schema =
    std::static_pointer_cast<parquet::schema::GroupNode>(
      parquet::schema::GroupNode::Make(
        "schema", parquet::Repetition::REQUIRED, fields));

  return parquet::StreamWriter{
    parquet::ParquetFileWriter::Open(outfile, schema, builder.build())};
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

void storeParquetResults(ArgumentParser args, ParquetData data_handler)
{
  LOG_INFO_FMT("Start storing results");

  // Initialize Send Columns
  std::vector<
    std::tuple<std::string, parquet::Type::type, parquet::ConvertedType::type>>
    send_cols{
      std::make_tuple(
        "messageID", parquet::Type::BYTE_ARRAY, parquet::ConvertedType::UTF8),
      std::make_tuple(
        "sendTime", parquet::Type::DOUBLE, parquet::ConvertedType::NONE)};

  // Initialize Response Columns
  std::vector<
    std::tuple<std::string, parquet::Type::type, parquet::ConvertedType::type>>
    response_cols{
      std::make_tuple(
        "messageID", parquet::Type::BYTE_ARRAY, parquet::ConvertedType::UTF8),
      std::make_tuple(
        "receiveTime", parquet::Type::DOUBLE, parquet::ConvertedType::NONE),
      std::make_tuple(
        "rawResponse",
        parquet::Type::BYTE_ARRAY,
        parquet::ConvertedType::UTF8)};

  // Write Send Parquet
  auto os = initParquetColumns(args.send_filepath, data_handler, send_cols);
  for (size_t i = 0; i < data_handler.SEND_TIME.size(); i++)
  {
    os << to_string(i) << data_handler.SEND_TIME[i] << parquet::EndRow;
  }

  // Write Response Parquet
  os = initParquetColumns(args.response_filepath, data_handler, response_cols);
  for (size_t i = 0; i < data_handler.RESPONSE_TIME.size(); i++)
  {
    os << to_string(i) << data_handler.RESPONSE_TIME[i]
       << data_handler.RAW_RESPONSE[i] << parquet::EndRow;
  }

  LOG_INFO_FMT("Finished storing results");
}

int main(int argc, char** argv)
{
  logger::config::default_init();
  CLI::App cli_app{"Perf Tool"};
  ArgumentParser args("Perf Tool", argv[0], cli_app);
  CLI11_PARSE(cli_app, argc, argv);

  ParquetData data_handler;
  std::vector<string> certificates = {args.cert, args.key, args.rootCa};

  readParquetFile(args.generator_filepath, data_handler);
  std::string server_address = args.server_address;

  // Keep only the host and port removing any https:// characters
  std::string separator = "//";
  auto exists_index = server_address.find(separator);
  if (exists_index != std::string::npos)
  {
    server_address = server_address.substr(exists_index + separator.length());
  }

  int max_block_write = 1000; // Threshold for maximum pending writes

  auto requests_size = data_handler.IDS.size();

  std::vector<timeval> start(requests_size);
  std::vector<timeval> end(requests_size);
  std::vector<std::vector<uint8_t>> raw_reqs(requests_size);

  // Store responses until they are processed to be written in parquet
  std::vector<std::vector<uint8_t>> resp_text(data_handler.IDS.size());
  // Add raw requests straight as uint8_t inside a vector
  for (size_t req = 0; req < requests_size; req++)
  {
    raw_reqs[req] = std::vector<uint8_t>(
      data_handler.REQUEST[req].begin(), data_handler.REQUEST[req].end());
  }

  LOG_INFO_FMT("Start Request Submission");

  if (!args.isPipeline)
  {
    // Request by Request
    for (size_t req = 0; req < requests_size; req++)
    {
      gettimeofday(&start[req], NULL);
      auto connection = create_connection(certificates, server_address);
      connection->write(raw_reqs[req]);
      resp_text[req] = connection->read_raw_response();
      gettimeofday(&end[req], NULL);
    }
  }
  else
  {
    // Pipeline
    int read_reqs = 0; // use this to block writes
    auto connection = create_connection(certificates, server_address);

    for (size_t req = 0; req < requests_size; req++)
    {
      gettimeofday(&start[req], NULL);
      connection->write(raw_reqs[req]);
      if (connection->bytes_available() or req - read_reqs > max_block_write)
      {
        resp_text[read_reqs] = connection->read_raw_response();
        gettimeofday(&end[read_reqs], NULL);
        read_reqs++;
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
    data_handler.RAW_RESPONSE.push_back(
      std::string(reinterpret_cast<char*>(resp_text[req].data())));
    double send_time = start[req].tv_sec + start[req].tv_usec / 1000000.0;
    double response_time = end[req].tv_sec + end[req].tv_usec / 1000000.0;
    data_handler.SEND_TIME.push_back(send_time);
    data_handler.RESPONSE_TIME.push_back(response_time);
  }

  storeParquetResults(args, data_handler);
}
