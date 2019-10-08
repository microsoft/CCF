
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"
#include "key_format.h"
#include "keypair.h"
#include "rw_keys.h"

static void myrand(unsigned char* output, size_t len)
{
  while (len > 0)
  {
    int use_len = len;
    if (use_len > sizeof(int))
    {
      use_len = sizeof(int);
    }
    int rnd = rand();
    memcpy(output, &rnd, use_len);
    output += use_len;
    len -= use_len;
  }
}

std::vector<uint8_t> random_message()
{
  std::vector<uint8_t> msg(32);
  for (unsigned i = 0; i < 32; i++)
  {
    myrand(&msg[i], 1);
  }
  return msg;
}

TEST_CASE("write/read public key and verify")
{
  KeyPair kp;
  auto msg = random_message();

  std::vector<uint8_t> sig = kp.sign(msg);

  auto raw_pubk = kp.get_public_sig_key();
  auto key_string = format::to_hex(raw_pubk, key_size);
  save_to_file(key_string, "kpfile");

  auto read_pubk_raw = read_from_file("kpfile");
  uint8_t key[32];
  format::from_hex(read_pubk_raw, key, key_size);
  PublicKey pub_key(key);

  CHECK(pub_key.verify(msg, sig));
}

TEST_CASE("write/read private key and verify")
{
  KeyPair kp;
  auto raw_privk = kp.get_private_key();
  auto key_string = format::to_hex(raw_privk, key_size);
  save_to_file(key_string, "kpfile_p");

  auto read_privk_raw = read_from_file("kpfile_p");
  uint8_t key[key_size];
  format::from_hex(read_privk_raw, key, key_size);
  KeyPair new_kp(key);

  auto msg = random_message();
  // sign with old
  std::vector<uint8_t> sig = kp.sign(msg);

  // verify with new
  PublicKey pks(new_kp.get_public_sig_key());
  CHECK(pks.verify(msg, sig));
}

TEST_CASE("write/read private key fails")
{
  KeyPair kp;
  auto raw_privk = kp.get_private_key();
  auto key_string = format::to_hex(raw_privk, key_size);
  save_to_file(key_string + "random", "kpfile_p");

  auto read_privk_raw = read_from_file("kpfile_p");
  uint8_t key[key_size];
  CHECK_THROWS_AS(
    format::from_hex(read_privk_raw, key, key_size), std::logic_error);
}

TEST_CASE("encrypt/decrypt")
{
  SUBCASE("succeeds")
  {
    KeyPair sender, receiver;
    uint8_t plaintext[16], encrypted[16], tag[16], decrypted[16];
    myrand(plaintext, 16);

    sender.encrypt(
      receiver.get_public_enc_key(), plaintext, 16, encrypted, tag);
    CHECK(
      receiver.decrypt(
        sender.get_public_enc_key(), encrypted, 16, decrypted, tag) == true);

    for (unsigned i = 0; i < 16; i++)
    {
      CHECK(plaintext[i] == decrypted[i]);
    }
  }

  SUBCASE("fails")
  {
    KeyPair sender, receiver;
    uint8_t plaintext[16], encrypted[16], tag[16], decrypted[16];
    myrand(plaintext, 16);

    sender.encrypt(
      receiver.get_public_enc_key(), plaintext, 16, encrypted, tag);
    encrypted[4] = 'X';
    CHECK(
      receiver.decrypt(
        sender.get_public_enc_key(), encrypted, 16, decrypted, tag) == false);
  }
}

// We need an explicit main to initialize and EverCrypt
int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  ::EverCrypt_AutoConfig2_init();
  int res = context.run();
  if (context.shouldExit())
  {
    return res;
  }
  return res;
}
