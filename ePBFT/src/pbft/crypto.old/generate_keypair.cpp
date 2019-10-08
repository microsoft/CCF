
#include "ds/logger.h"
#include "key_format.h"
#include "keypair.h"
#include "rw_keys.h"

int main(int argc, char** argv)
{
  std::string prefix = "keys";
  if (argc > 1)
  {
    prefix = argv[1];
  }
  KeyPair kp;
  std::stringstream ss;
  {
    auto raw_pubk = kp.get_public_sig_key();
    auto key_string = format::to_hex(raw_pubk, key_size);
    ss << key_string << ", ";
  }
  {
    auto raw_pubk_enc = kp.get_public_enc_key();
    auto key_string = format::to_hex(raw_pubk_enc, key_size);
    ss << key_string << ", ";
  }
  {
    auto raw_privk = kp.get_private_key();
    auto key_string = format::to_hex(raw_privk, key_size);
    ss << key_string << "\n";
    save_to_file(ss.str(), prefix + "_keys");
  }

  std::cout << "generated keys in files with prefix: " << prefix << std::endl;
  return 0;
}
