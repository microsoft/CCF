#include <arpa/inet.h>
#include <cassert>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std;

std::string client_cert =
  "-----BEGIN "
  "CERTIFICATE-----\nMIIBqzCCATOgAwIBAgIQd+"
  "d1sDB0aFNqSrqCDfvJ9TAKBggqhkjOPQQDAzARMQ8w\nDQYDVQQDDAZpc3N1ZXIwHhcNMjUwNTA2"
  "MTI0MTI4WhcNMjYwNTA2MTI0MTI3WjAR\nMQ8wDQYDVQQDDAZzZXJ2ZXIwdjAQBgcqhkjOPQIBBg"
  "UrgQQAIgNiAAQWQ9pXpkjS\nrBspuin2lxlVkRF4P71qgUFxI0OPhjwpoW7F4XZ3nQw9Fm1l9D04"
  "xKmQjLSnDILI\nQ6CxOi2Vcge3bBiRq7C0g/"
  "eyRwFtTlRPIAjPWkfIpzemzxBi1nsJ89OjUDBOMAwG\nA1UdEwEB/"
  "wQCMAAwHQYDVR0OBBYEFLgq+"
  "0oTGd3LcWKU30k0JYs02vGRMB8GA1Ud\nIwQYMBaAFC5QSZgcVvKdFM6iuCdE6BWCjIMWMAoGCCq"
  "GSM49BAMDA2YAMGMCL0In\nDcPORuNOSg3NlkrfsM33zpfPbyY1xe/"
  "ucORyQ4o0BbbS955VUjpjiqGrFVG9AjAZ\n81MHyJEdjq6MfsWkk6ZCKVgcpUPSyqf+gw956h/"
  "BZpzvROGd+2VbQgvA3YVR118=\n-----END CERTIFICATE-----\n";
std::string client_key =
  "-----BEGIN PRIVATE "
  "KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC5+"
  "n9hBSdxoPkOW29R\nZfgFsJvaaZVsswZgPzTLi5c/"
  "gi1EXaBJ9G3W89QhxT+"
  "0xNehZANiAAQWQ9pXpkjS\nrBspuin2lxlVkRF4P71qgUFxI0OPhjwpoW7F4XZ3nQw9Fm1l9D04x"
  "KmQjLSnDILI\nQ6CxOi2Vcge3bBiRq7C0g/"
  "eyRwFtTlRPIAjPWkfIpzemzxBi1nsJ89M=\n-----END PRIVATE KEY-----\n";
std::string server_cert =
  "-----BEGIN "
  "CERTIFICATE-----"
  "\nMIIBrjCCATOgAwIBAgIQUIfvcdN6IqNLAi1cWnI2pzAKBggqhkjOPQQDAzARMQ8w\nDQYDVQQD"
  "DAZpc3N1ZXIwHhcNMjUwNTA2MTI0MTI4WhcNMjYwNTA2MTI0MTI3WjAR\nMQ8wDQYDVQQDDAZjbG"
  "llbnQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS5KBoa7gzx\nS+NTpo2QpYmSE27pJSbCCLVW/"
  "7F7WHTb3WFUa1TOXXeEAfXpz//De+f2tcw7A9Lq\nZgG7K8BLU9Qq1Tfbi+l3eqRyKgh2/"
  "Fjcfjj+zMbaeeebc2UpISiMuM6jUDBOMAwG\nA1UdEwEB/"
  "wQCMAAwHQYDVR0OBBYEFHQxv2qweoSekjnlXXIYx5SLxABKMB8GA1Ud\nIwQYMBaAFC5QSZgcVvK"
  "dFM6iuCdE6BWCjIMWMAoGCCqGSM49BAMDA2kAMGYCMQDL\nM37xLv8AoqKaVsa2TlcSkriJzkI1H"
  "+s7eT/"
  "vhiWqdzzYueK1EgnmUTfKYDXU7ZUC\nMQD41k03B0d0b4ayKikF6071EN5PrKadnET8G9eb/"
  "9zgmveGAsOMzg+dzDRsnzNe\nMEo=\n-----END CERTIFICATE-----\n";
std::string server_key =
  "-----BEGIN PRIVATE "
  "KEY-----"
  "\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBhT1b8io0e5NGXTGpU\nKB98upN8"
  "fQo1l429qO/"
  "RJCWXk0Yiu4a2jh8LHqVvdrENw6ahZANiAAS5KBoa7gzx\nS+NTpo2QpYmSE27pJSbCCLVW/"
  "7F7WHTb3WFUa1TOXXeEAfXpz//De+f2tcw7A9Lq\nZgG7K8BLU9Qq1Tfbi+l3eqRyKgh2/"
  "Fjcfjj+zMbaeeebc2UpISiMuM4=\n-----END PRIVATE KEY-----\n";

class TestPipe
{
  int pfd[2];

public:
  static const int SERVER = 0;
  static const int CLIENT = 1;

  TestPipe()
  {
    if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pfd) == -1)
    {
      throw runtime_error(
        "Failed to create socketpair: " + string(strerror(errno)));
    }
  }
  ~TestPipe()
  {
    close(pfd[0]);
    close(pfd[1]);
  }

  size_t send(int id, const uint8_t* buf, size_t len)
  {
    int rc = write(pfd[id], buf, len);
    if (rc == -1)
      std::cout << "Error while reading: " << strerror(errno) << std::endl;
    return rc;
  }

  size_t recv(int id, uint8_t* buf, size_t len)
  {
    int rc = read(pfd[id], buf, len);
    if (rc == -1)
      std::cout << "Error while reading: " << strerror(errno) << std::endl;
    return rc;
  }
};

/// Callback wrapper around TestPipe->send().
template <int end>
int send(void* ctx, const uint8_t* buf, size_t len)
{
  auto pipe = reinterpret_cast<TestPipe*>(ctx);
  int rc = pipe->send(end, buf, len);
  assert(rc == len);
  return rc;
}

/// Callback wrapper around TestPipe->recv().
template <int end>
int recv(void* ctx, uint8_t* buf, size_t len)
{
  auto pipe = reinterpret_cast<TestPipe*>(ctx);
  int rc = pipe->recv(end, buf, len);
  assert(rc == len);
  return rc;
}

// OpenSSL callbacks that call onto the pipe's ones
template <int end>
long send(
  BIO* b,
  int oper,
  const char* argp,
  size_t len,
  int argi,
  long argl,
  int ret,
  size_t* processed)
{
  // Unused arguments
  (void)argi;
  (void)argl;
  (void)processed;

  if (ret && oper == (BIO_CB_WRITE | BIO_CB_RETURN))
  {
    // Flush the BIO so the "pipe doesn't clog", but we don't use the
    // data here, because 'argp' already has it.
    BIO_flush(b);
    size_t pending = BIO_pending(b);
    if (pending)
      BIO_reset(b);

    // Pipe object
    auto pipe = reinterpret_cast<TestPipe*>(BIO_get_callback_arg(b));
    size_t put = send<end>(pipe, (const uint8_t*)argp, len);
    assert(put == len);
  }

  // Unless we detected an error, the return value is always the same as the
  // original operation.
  return ret;
}

template <int end>
long recv(
  BIO* b,
  int oper,
  const char* argp,
  size_t len,
  int argi,
  long argl,
  int ret,
  size_t* processed)
{
  // Unused arguments
  (void)argi;
  (void)argl;

  if (ret && oper == (BIO_CB_READ | BIO_CB_RETURN))
  {
    // Pipe object
    auto pipe = reinterpret_cast<TestPipe*>(BIO_get_callback_arg(b));
    size_t got = recv<end>(pipe, (uint8_t*)argp, len);

    // Got nothing, return "WANTS READ"
    if (got <= 0)
      return ret;

    // Write to the actual BIO so SSL can use it
    BIO_write_ex(b, argp, got, processed);

    // If original return was -1 because it didn't find anything to read, return
    // 1 to say we actually read something
    if (got > 0 && ret < 0)
      return 1;
  }

  // Unless we detected an error, the return value is always the same as the
  // original operation.
  return ret;
}

void set_bio(
  SSL* ssl, void* cb_obj, BIO_callback_fn_ex send, BIO_callback_fn_ex recv)
{
  // Read/Write BIOs will be used by TLS
  BIO* rbio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(rbio, -1);
  BIO_set_callback_arg(rbio, (char*)cb_obj);
  BIO_set_callback_ex(rbio, recv);
  SSL_set0_rbio(ssl, rbio);

  BIO* wbio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(wbio, -1);
  BIO_set_callback_arg(wbio, (char*)cb_obj);
  BIO_set_callback_ex(wbio, send);
  SSL_set0_wbio(ssl, wbio);
}

void init_actor(SSL_CTX* cfg, SSL* ssl, bool client)
{
  // Require at least TLS 1.2, support up to 1.3
  SSL_CTX_set_min_proto_version(cfg, TLS1_2_VERSION);
  SSL_set_min_proto_version(ssl, TLS1_2_VERSION);

  // Disable renegotiation to avoid DoS
  SSL_CTX_set_options(
    cfg,
    SSL_OP_CIPHER_SERVER_PREFERENCE |
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_NO_RENEGOTIATION);
  SSL_set_options(
    ssl,
    SSL_OP_CIPHER_SERVER_PREFERENCE |
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_NO_RENEGOTIATION);

  // Set cipher for TLS 1.2
  const auto cipher_list =
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256";
  SSL_CTX_set_cipher_list(cfg, cipher_list);
  SSL_set_cipher_list(ssl, cipher_list);

  // Set cipher for TLS 1.3
  const auto ciphersuites =
    "TLS_AES_256_GCM_SHA384:"
    "TLS_AES_128_GCM_SHA256";
  SSL_CTX_set_ciphersuites(cfg, ciphersuites);
  SSL_set_ciphersuites(ssl, ciphersuites);

  // Restrict the curves to approved ones
  SSL_CTX_set1_curves_list(cfg, "P-521:P-384:P-256");
  SSL_set1_curves_list(ssl, "P-521:P-384:P-256");

  // Allow buffer to be relocated between WANT_WRITE retries, and do partial
  // writes if possible
  SSL_CTX_set_mode(
    cfg, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_set_mode(
    ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

  // Initialise connection
  if (client)
    SSL_set_connect_state(ssl);
  else
    SSL_set_accept_state(ssl);
}

void actor(bool client, TestPipe& pipe)
{
  SSL_CTX* ctx =
    SSL_CTX_new(client ? TLS_client_method() : TLS_server_method());
  SSL* ssl = SSL_new(ctx);

  init_actor(ctx, ssl, client);

  auto cb = [](int, x509_store_ctx_st*) { return 1; };
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cb);
  SSL_set_verify(ssl, SSL_VERIFY_PEER, cb);

  X509* own_cert = nullptr;
  EVP_PKEY* own_pkey = nullptr;

  if (client)
  {
    BIO* mem = BIO_new_mem_buf(client_cert.data(), client_cert.size());
    own_cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
    BIO_free(mem);
    mem = BIO_new_mem_buf(client_key.data(), client_key.size());
    own_pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
    BIO_free(mem);
  }
  else
  {
    BIO* mem = BIO_new_mem_buf(server_cert.data(), server_cert.size());
    own_cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
    BIO_free(mem);
    mem = BIO_new_mem_buf(server_key.data(), server_key.size());
    own_pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
    BIO_free(mem);
  }

  assert(SSL_CTX_use_cert_and_key(ctx, own_cert, own_pkey, NULL, 1) == 1);
  assert(SSL_use_cert_and_key(ssl, own_cert, own_pkey, NULL, 1) == 1);

  if (client)
  {
    set_bio(ssl, &pipe, send<TestPipe::CLIENT>, recv<TestPipe::CLIENT>);
  }
  else
  {
    set_bio(ssl, &pipe, send<TestPipe::SERVER>, recv<TestPipe::SERVER>);
  }

  // int rc = 0;
  int rc = SSL_do_handshake(ssl);

  if (client)
  {
    std::cerr << "Handshake client result: " << rc << std::endl;
  }
  else
  {
    std::cout << "Handshake server result: " << rc << std::endl;
  }

  X509_free(own_cert);
  EVP_PKEY_free(own_pkey);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

void run_test_case()
{
  TestPipe pipe;

  thread client_thread([&]() { actor(true, pipe); });
  thread server_thread([&]() { actor(false, pipe); });

  client_thread.join();
  server_thread.join();

  std::cout << "Test completed" << std::endl;
}

int main()
{
  run_test_case();
}