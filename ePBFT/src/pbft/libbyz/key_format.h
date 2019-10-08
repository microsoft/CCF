
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace format
{
  void from_hex(std::string key, uint8_t* dst, size_t dst_size);
  // takes a string "key" in hex format and saves it as a byte array of size
  // "dst_size" in "dst" throws logic error if the key is longer than "dst_size"

  std::string to_hex(uint8_t* key, size_t size);
  // takes a byte array "key" and it's size "size" and returns a string of its
  // representation in hex format

} // namespace format