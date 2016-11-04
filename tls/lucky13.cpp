/******************************************************************************
**
** Copyright (C) 2016 Graz University of Technology
**
** Contact: itsec-team@iaik.tugraz.at
**
** IT-SECURITY LICENSE
** Version 1.2, 1st of October 2016
**
** This framework may only be used within the IT-Security exercises 2016. Only
** students that are formally registered within TUGRAZ-online may use it until
** 30th of June 2016. After that date, licensees have the duty to safely
** delete the software framework.
**
** This license does not grant you any rights to re-distribute the software,
** to change the license, to grant access to other individuals, and to
** commercially use the software.
**
** This software is distributed WITHOUT ANY WARRANTY; without even the implied
** warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
**
** If you are interested in a more reasonable license, please use the contact
** information above.
**
******************************************************************************/

#include <fstream>
#include <iostream>
#include <vector>

#include "attack.h"
#include "endian.h"
#include "oracle.h"

namespace
{
  void print_usage(const std::string& progname)
  {
    std::cout << "usage:" << std::endl;
    std::cout << progname << " attack_local_tsc <challenge> <output>" << std::endl;
  }
}

int main(int argc, char** argv)
{
  if (argc != 4)
  {
    print_usage(argv[0]);
    return 1;
  }

  const std::string command(argv[1]);
  const std::string challenge_file(argv[2]);
  const std::string output_file(argv[3]);

  local_oracle::clock_type clock_type;
  if (command == "attack_local_tsc")
    clock_type = local_oracle::RDTSC;
  else
  {
    print_usage(argv[0]);
    return 1;
  }

  oracle::ciphersuite::block_cipher_key bc_key;
  oracle::ciphersuite::hmac_key hmac_key;
  oracle::ciphersuite::record original_record;

  {
    std::ifstream ifs(challenge_file.c_str());
    if (!ifs)
    {
      std::cout << "Failed to open " << challenge_file << "!" << std::endl;
      return 1;
    }

    ifs.read(reinterpret_cast<char*>(bc_key.data()), bc_key.size());
    ifs.read(reinterpret_cast<char*>(hmac_key.data()), hmac_key.size());
    ifs.read(reinterpret_cast<char*>(&original_record.header), sizeof(original_record.header));
    ifs.read(reinterpret_cast<char*>(original_record.iv.data()), original_record.iv.size());

    original_record.ciphertext.resize(ntoh(original_record.header.length) -
                                      original_record.iv.size());
    ifs.read(reinterpret_cast<char*>(original_record.ciphertext.data()),
             original_record.ciphertext.size());
  }

  local_oracle oracle(bc_key, hmac_key, clock_type);

  // Encrypt the original plain text.
  std::vector<uint8_t> recovered_plaintext;

  if (clock_type == local_oracle::RDTSC)
    recovered_plaintext = lucky13_tsc(original_record, oracle);
  else
    recovered_plaintext = lucky13_pe(original_record, oracle);

  std::ofstream ofs(output_file.c_str());
  if (!ofs)
  {
    std::cout << "Failed to open " << challenge_file << "!" << std::endl;
    return 1;
  }

  ofs.write(reinterpret_cast<const char*>(recovered_plaintext.data()), recovered_plaintext.size());
}
