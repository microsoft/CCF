
#include <fstream>
#include <string>

void save_to_file(const std::string& key, const std::string& file_name)
{
  std::ofstream file(file_name);
  file << key;
  file.close();
}

std::string read_from_file(std::string file_name)
{
  std::ifstream file(file_name);
  std::string s;
  file >> std::hex >> s;
  file.close();
  return s;
}
