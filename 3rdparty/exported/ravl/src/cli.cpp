#include <fstream>
#include <iostream>
#include <ravl/options.h>
#include <ravl/ravl.h>
#include <sstream>

int main(int argc, const char** argv)
{
  std::cout << argc << std::endl;

  try
  {
    if (argc == 1)
    {
      std::cout << "Usage: " << argv[0] << " <filename>\n" << std::endl;
      return 1;
    }
    else
    {
      ravl::Options options = {
        .verbosity = 1, .certificate_verification = {.ignore_time = true}};

      for (int i = 1; i < argc; i++)
      {
        std::ifstream is(argv[i]);
        if (!is.good())
        {
          std::cout << "Warning: error opening '" << argv[i] << "', skipping."
                    << std::endl;
          continue;
        }

        std::stringstream sstr;
        sstr << is.rdbuf();
        auto attestation = ravl::parse_attestation(sstr.str());

        try
        {
          auto claims = verify(attestation, options);
        }
        catch (const std::exception& ex)
        {
          std::cout << "Error: verification of '" << argv[i]
                    << "' failed: " << ex.what();
        }
      }
    }
  }
  catch (const std::exception& ex)
  {
    std::cout << "Exception: " << ex.what() << std::endl;
    return 2;
  }
  catch (...)
  {
    std::cout << "Caught unknown exception" << std::endl;
    return 2;
  }

  return 0;
}