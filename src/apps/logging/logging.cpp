// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/appinterface.h"
#include "formatters.h"
#include "logging_schema.h"
#include "node/quote.h"
#include "node/rpc/userfrontend.h"

#include <fmt/format_header_only.h>
#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

using namespace std;
using namespace nlohmann;
using namespace ccf;

namespace ccfapp
{
  struct Procs
  {
    static constexpr auto LOG_RECORD = "LOG_record";
    static constexpr auto LOG_GET = "LOG_get";

    static constexpr auto LOG_RECORD_PUBLIC = "LOG_record_pub";
    static constexpr auto LOG_GET_PUBLIC = "LOG_get_pub";

    static constexpr auto LOG_RECORD_PREFIX_CERT = "LOG_record_prefix_cert";
    static constexpr auto LOG_RECORD_ANONYMOUS_CALLER = "LOG_record_anonymous";
  };

  // SNIPPET: table_definition
  using Table = Store::Map<size_t, string>;

  // SNIPPET: inherit_frontend
  class LoggerHandlers : public UserHandlerRegistry
  {
  private:
    Table& records;
    Table& public_records;
    CodeIDs& user_code_ids;

    const nlohmann::json record_public_params_schema;
    const nlohmann::json record_public_result_schema;

    const nlohmann::json get_public_params_schema;
    const nlohmann::json get_public_result_schema;

    std::optional<std::string> validate(
      const nlohmann::json& params, const nlohmann::json& j_schema)
    {
      valijson::Schema schema;
      valijson::SchemaParser parser;
      valijson::adapters::NlohmannJsonAdapter schema_adapter(j_schema);
      parser.populateSchema(schema_adapter, schema);

      valijson::Validator validator;
      valijson::ValidationResults results;
      valijson::adapters::NlohmannJsonAdapter params_adapter(params);

      if (!validator.validate(schema, params_adapter, &results))
      {
        return fmt::format("Error during validation:\n\t{}", results);
      }

      return std::nullopt;
    }

  public:
    // SNIPPET_START: constructor
    LoggerHandlers(NetworkTables& nwt, AbstractNotifier& notifier) :
      UserHandlerRegistry(nwt),
      records(
        nwt.tables->create<Table>("records", kv::SecurityDomain::PRIVATE)),
      public_records(nwt.tables->create<Table>(
        "public_records", kv::SecurityDomain::PUBLIC)),
      // SNIPPET_END: constructor
      user_code_ids(*nwt.tables->get<CodeIDs>(Tables::USER_CODE_IDS)),
      record_public_params_schema(nlohmann::json::parse(j_record_public_in)),
      record_public_result_schema(nlohmann::json::parse(j_record_public_out)),
      get_public_params_schema(nlohmann::json::parse(j_get_public_in)),
      get_public_result_schema(nlohmann::json::parse(j_get_public_out))
    {
      // SNIPPET_START: record
      // SNIPPET_START: macro_validation_record
      auto record = [this](Store::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRecord::In>();
        // SNIPPET_END: macro_validation_record

        if (in.msg.empty())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Cannot record an empty log message");
        }

        auto view = tx.get_view(records);
        view->put(in.id, in.msg);
        return make_success(true);
      };
      // SNIPPET_END: record

      // SNIPPET_START: get
      auto get = [this](Store::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingGet::In>();
        auto view = tx.get_view(records);
        auto r = view->get(in.id);

        if (r.has_value())
          return make_success(LoggingGet::Out{r.value()});

        return make_error(
          HTTP_STATUS_BAD_REQUEST, fmt::format("No such record: {}", in.id));
      };
      // SNIPPET_END: get

      // SNIPPET_START: record_public
      // SNIPPET_START: valijson_record_public
      auto record_public = [this](Store::Tx& tx, nlohmann::json&& params) {
        const auto validation_error =
          validate(params, record_public_params_schema);

        if (validation_error.has_value())
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, *validation_error);
        }
        // SNIPPET_END: valijson_record_public

        const auto msg = params["msg"].get<std::string>();
        if (msg.empty())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Cannot record an empty log message");
        }

        auto view = tx.get_view(public_records);
        view->put(params["id"], msg);
        return make_success(true);
      };
      // SNIPPET_END: record_public

      // SNIPPET_START: get_public
      auto get_public = [this](Store::Tx& tx, nlohmann::json&& params) {
        const auto validation_error =
          validate(params, get_public_params_schema);

        if (validation_error.has_value())
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, *validation_error);
        }

        auto view = tx.get_view(public_records);
        const auto id = params["id"];
        auto r = view->get(id);

        if (r.has_value())
        {
          auto result = nlohmann::json::object();
          result["msg"] = r.value();
          return make_success(result);
        }

        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          fmt::format("No such record: {}", id.dump()));
      };
      // SNIPPET_END: get_public

      // SNIPPET_START: log_record_prefix_cert
      auto log_record_prefix_cert = [this](RequestArgs& args) {
        mbedtls_x509_crt cert;
        mbedtls_x509_crt_init(&cert);

        const auto& cert_data = args.rpc_ctx->session->caller_cert;
        const auto ret =
          mbedtls_x509_crt_parse(&cert, cert_data.data(), cert_data.size());

        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());

        const auto in = body_j.get<LoggingRecord::In>();
        if (in.msg.empty())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body("Cannot record an empty log message");
          return;
        }

        const auto log_line = fmt::format("{}: {}", cert.subject, in.msg);
        auto view = args.tx.get_view(records);
        view->put(in.id, log_line);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        args.rpc_ctx->set_response_body(nlohmann::json(true).dump());
      };
      // SNIPPET_END: log_record_prefix_cert

      auto log_record_anonymous = [this](
                                    RequestArgs& args,
                                    nlohmann::json&& params) {
        const auto in = params.get<LoggingRecord::In>();

        std::vector<uint8_t> raw_quote = tls::raw_from_b64(
          "AQAAAAIAAADoEQAAAAAAAAMAAgAAAAAABQAKAJOacjP3nEyplAoNs5V/"
          "BgeCxRncHRJNAnFOMevznz//AAAAAA4OAwX/"
          "gAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAA"
          "BwAAAAAAAAD2Luo2MMg7y01vnv5/"
          "+UGhP2OYLBUxiglYdmhSoHOOHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "yprXMxRImAqiiJDOc+QzY4N38XmrRFay/"
          "iNxkxk6jQoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AABAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAAAAAAAAAAAAAAAAABtfDuxAyIGMx+"
          "duKJyTYv2Gyc3pWQbqNQCbUs8mNAnoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAADQQAAB343quFO1a7HhkwuXC8shYxdZQHAVK9Cw747XnDAueqYGsqgazae+"
          "TsDvvgD9fNjgslJKoMS2Pve7C3geQoCzs75QNLkK2gvm9/YO//"
          "JoSU8KW632Ko3UNBEQDFe9mRK/X3k5pf8pPz/"
          "53jLbGuQjn+B4mrxi2nvWTZyKleXSIVw4OAwX/"
          "gAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABUAAAAAAAAA"
          "BwAAAAAAAADNyt+32yKtpf1gNFXN4b+"
          "folj6XyhNzW4MYzkvYzoRBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjE9"
          "XddeWUD6WE393xoqCmgBWrI3tcBQLCBsJRJDFe/"
          "8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUAAA"
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AAAAAAAAAABRC3TS4+d5bZVOx/"
          "dfq71J9g3q06PJR8j8CjLmQy8g8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          "AFm5iCWVhJFXKD6FcsNpcDG+1ar0Kq+FqP7GxsP2zSFGVtPME803k3W0Q2H+"
          "OBVvGpK5Iprq45k1aYeZpLHe3bEgAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhsc"
          "HR4fBQDMDQAALS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVnRENDQkNhZ0F3"
          "SUJBZ0lVYmkvNEpMN3ZQd2hzVkk1Mys2MXgrZWRPSW5vd0NnWUlLb1pJemowRUF3SXcK"
          "Y1RFak1DRUdBMVVFQXd3YVNXNTBaV3dnVTBkWUlGQkRTeUJRY205alpYTnpiM0lnUTBF"
          "eEdqQVlCZ05WQkFvTQpFVWx1ZEdWc0lFTnZjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhE"
          "QXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFCkNBd0NRMEV4Q3pBSkJnTlZCQVlUQWxW"
          "VE1CNFhEVEl3TURNeU1EQTRNemN5TlZvWERUSTNNRE15TURBNE16Y3kKTlZvd2NERWlN"
          "Q0FHQTFVRUF3d1pTVzUwWld3Z1UwZFlJRkJEU3lCRFpYSjBhV1pwWTJGMFpURWFNQmdH"
          "QTFVRQpDZ3dSU1c1MFpXd2dRMjl5Y0c5eVlYUnBiMjR4RkRBU0JnTlZCQWNNQzFOaGJu"
          "UmhJRU5zWVhKaE1Rc3dDUVlEClZRUUlEQUpEUVRFTE1Ba0dBMVVFQmhNQ1ZWTXdXVEFU"
          "QmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUS8KSDltbEVHRGhIclUwL1FabHNj"
          "eDNXdjc0d0Y2emtXNFZCZEM0S1lJRGxxeUI3blhNRUlZWWNGTDlZdHRRa1pFdAowbGJU"
          "OURkNm9jenB0dUhOdnRkOW80SUNtekNDQXBjd0h3WURWUjBqQkJnd0ZvQVUwT2lxMm5Y"
          "WCtTNUpGNWc4CmV4UmwwTlh5V1Uwd1h3WURWUjBmQkZnd1ZqQlVvRktnVUlaT2FIUjBj"
          "SE02THk5aGNHa3VkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzl6WjNn"
          "dlkyVnlkR2xtYVdOaGRHbHZiaTkyTVM5d1kydGpjbXcvWTJFOQpjSEp2WTJWemMyOXlN"
          "QjBHQTFVZERnUVdCQlNRTEdaWEkvelVCeXJoS0lrakl0cTNxVDl1V3pBT0JnTlZIUThC"
          "CkFmOEVCQU1DQnNBd0RBWURWUjBUQVFIL0JBSXdBRENDQWRRR0NTcUdTSWI0VFFFTkFR"
          "U0NBY1V3Z2dIQk1CNEcKQ2lxR1NJYjRUUUVOQVFFRUVIbkNNblVGOVgxV1JIT2tlNndY"
          "RnhVd2dnRmtCZ29xaGtpRytFMEJEUUVDTUlJQgpWREFRQmdzcWhraUcrRTBCRFFFQ0FR"
          "SUJEVEFRQmdzcWhraUcrRTBCRFFFQ0FnSUJEVEFRQmdzcWhraUcrRTBCCkRRRUNBd0lC"
          "QWpBUUJnc3Foa2lHK0UwQkRRRUNCQUlCQkRBUUJnc3Foa2lHK0UwQkRRRUNCUUlCQVRB"
          "UkJnc3EKaGtpRytFMEJEUUVDQmdJQ0FJQXdFQVlMS29aSWh2aE5BUTBCQWdjQ0FRSXdF"
          "QVlMS29aSWh2aE5BUTBCQWdnQwpBUUF3RUFZTEtvWklodmhOQVEwQkFna0NBUUF3RUFZ"
          "TEtvWklodmhOQVEwQkFnb0NBUUF3RUFZTEtvWklodmhOCkFRMEJBZ3NDQVFBd0VBWUxL"
          "b1pJaHZoTkFRMEJBZ3dDQVFBd0VBWUxLb1pJaHZoTkFRMEJBZzBDQVFBd0VBWUwKS29a"
          "SWh2aE5BUTBCQWc0Q0FRQXdFQVlMS29aSWh2aE5BUTBCQWc4Q0FRQXdFQVlMS29aSWh2"
          "aE5BUTBCQWhBQwpBUUF3RUFZTEtvWklodmhOQVEwQkFoRUNBUWt3SHdZTEtvWklodmhO"
          "QVEwQkFoSUVFQTBOQWdRQmdBSUFBQUFBCkFBQUFBQUF3RUFZS0tvWklodmhOQVEwQkF3"
          "UUNBQUF3RkFZS0tvWklodmhOQVEwQkJBUUdBSkJ1MVFBQU1BOEcKQ2lxR1NJYjRUUUVO"
          "QVFVS0FRQXdDZ1lJS29aSXpqMEVBd0lEU0FBd1JRSWhBUHZabUtoZjh6NVpPYW5ScWRX"
          "VQoxb1VUZnFvVGlsU2RKZzZ6MmpTeExlNkJBaUFjTE1Ja1g4V0VwZFZsQisvMko0TFpl"
          "RFBOKzlVRTh4RHlLazZBCjQrVHFXQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
          "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNsekNDQWo2Z0F3SUJBZ0lWQU5E"
          "b3F0cDExL2t1U1JlWVBIc1VaZERWOGxsTk1Bb0dDQ3FHU000OUJBTUMKTUdneEdqQVlC"
          "Z05WQkFNTUVVbHVkR1ZzSUZOSFdDQlNiMjkwSUVOQk1Sb3dHQVlEVlFRS0RCRkpiblJs"
          "YkNCRApiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6"
          "QUpCZ05WQkFnTUFrTkJNUXN3CkNRWURWUVFHRXdKVlV6QWVGdzB4T0RBMU1qRXhNRFEx"
          "TURoYUZ3MHpNekExTWpFeE1EUTFNRGhhTUhFeEl6QWgKQmdOVkJBTU1Ha2x1ZEdWc0lG"
          "TkhXQ0JRUTBzZ1VISnZZMlZ6YzI5eUlFTkJNUm93R0FZRFZRUUtEQkZKYm5SbApiQ0JE"
          "YjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdO"
          "VkJBZ01Ba05CCk1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdT"
          "TTQ5QXdFSEEwSUFCTDlxK05NcDJJT2cKdGRsMWJrL3VXWjUrVEdRbThhQ2k4ejc4ZnMr"
          "ZktDUTNkK3VEelhuVlRBVDJaaERDaWZ5SXVKd3ZOM3dOQnA5aQpIQlNTTUpNSnJCT2pn"
          "YnN3Z2Jnd0h3WURWUjBqQkJnd0ZvQVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3"
          "ClVnWURWUjBmQkVzd1NUQkhvRVdnUTRaQmFIUjBjSE02THk5alpYSjBhV1pwWTJGMFpY"
          "TXVkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzlKYm5SbGJGTkhXRkp2"
          "YjNSRFFTNWpjbXd3SFFZRFZSME9CQllFRk5EbwpxdHAxMS9rdVNSZVlQSHNVWmREVjhs"
          "bE5NQTRHQTFVZER3RUIvd1FFQXdJQkJqQVNCZ05WSFJNQkFmOEVDREFHCkFRSC9BZ0VB"
          "TUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUMvOWorODRUK0h6dFZPL3NPUUJXSmJTZCsv"
          "MnVleEsKNCthQTBqY0ZCTGNwQWlBM2RoTXJGNWNENTJ0NkZxTXZBSXBqOFhkR215MmJl"
          "ZWxqTEpLK3B6cGNSQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJ"
          "TiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqakNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56"
          "ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNX"
          "NTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2"
          "Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3"
          "Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdOREV4TVZvWERUTXpN"
          "RFV5TVRFd05ERXhNRm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNR"
          "Z1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURW"
          "UVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlU"
          "CkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVla"
          "T2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhP"
          "NG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dC"
          "UWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJE"
          "aGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhN"
          "dWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtTnliREFkQmdOVkhRNEVG"
          "Z1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdF"
          "R01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNBQXdS"
          "UUlnUVFzLzA4cnljZFBhdUNGazhVUFFYQ01BbHNsb0JlN053YVFHVGNkcGEwRUMKSVFD"
          "VXQ4U0d2eEttanBjTS96MFdQOUR2bzhoMms1ZHUxaVdEZEJrQW4rMGlpQT09Ci0tLS0t"
          "RU5EIENFUlRJRklDQVRFLS0tLS0KAA==");

        auto digest_raw =
          tls::raw_from_b64("9i7qNjDIO8tNb57+f/lBoT9jmCwVMYoJWHZoUqBzjh4=");

        CodeDigest array_digest;
        std::copy_n(digest_raw.begin(), CODE_DIGEST_BYTES, array_digest.begin());

        auto uc_view = args.tx.get_view(user_code_ids);
        uc_view->put(array_digest, CodeStatus::ACCEPTED);

#ifdef GET_QUOTE
        auto rc = ccf::QuoteVerifier::verify_quote_against_store(
          args.tx,
          user_code_ids,
          raw_quote,
          tls::cert_der_to_pem(args.rpc_ctx->session->caller_cert));
        if (rc != QuoteVerificationResult::VERIFIED)
        {
          const auto [code, message] =
            QuoteVerifier::quote_verification_error(rc);
          return make_error(code, message);
        }
#endif

        if (in.msg.empty())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Cannot record an empty log message");
        }

        const auto log_line = fmt::format("Anonymous: {}", in.msg);
        auto view = args.tx.get_view(records);
        view->put(in.id, log_line);
        return make_success(true);
      };

      install(Procs::LOG_RECORD, json_adapter(record), Write)
        .set_auto_schema<LoggingRecord::In, bool>();
      // SNIPPET_START: install_get
      install(Procs::LOG_GET, json_adapter(get), Read)
        .set_auto_schema<LoggingGet>();
      // SNIPPET_END: install_get

      install(Procs::LOG_RECORD_PUBLIC, json_adapter(record_public), Write)
        .set_params_schema(record_public_params_schema)
        .set_result_schema(record_public_result_schema);

      install(Procs::LOG_GET_PUBLIC, json_adapter(get_public), Read)
        .set_params_schema(get_public_params_schema)
        .set_result_schema(get_public_result_schema);

      install(Procs::LOG_RECORD_PREFIX_CERT, log_record_prefix_cert, Write);
      install(
        Procs::LOG_RECORD_ANONYMOUS_CALLER,
        json_adapter(log_record_anonymous),
        Write)
        .set_auto_schema<LoggingRecord::In, bool>()
        .set_require_client_identity(false);

      nwt.signatures.set_global_hook([this, &notifier](
                                       kv::Version version,
                                       const Signatures::State& s,
                                       const Signatures::Write& w) {
        if (w.size() > 0)
        {
          nlohmann::json notify_j;
          notify_j["commit"] = version;
          notifier.notify(jsonrpc::pack(notify_j, jsonrpc::Pack::Text));
        }
      });
    }
  };

  class Logger : public ccf::UserRpcFrontend
  {
  private:
    LoggerHandlers logger_handlers;

  public:
    Logger(NetworkTables& network, AbstractNotifier& notifier) :
      ccf::UserRpcFrontend(*network.tables, logger_handlers),
      logger_handlers(network, notifier)
    {}
  };

  // SNIPPET_START: rpc_handler
  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& nwt, AbstractNotifier& notifier)
  {
    return make_shared<Logger>(nwt, notifier);
  }
  // SNIPPET_END: rpc_handler
}
