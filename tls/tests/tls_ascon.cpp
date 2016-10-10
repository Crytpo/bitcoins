/******************************************************************************
**
** Copyright (C) 2016 Graz University of Technology
**
** Contact: itsec-team@iaik.tugraz.at
**
** IT-SECURITY LICENSE
** Version 1.1, 12th of March 2016
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

#include "../endian.h"
#include "../tls-ascon.h"
#include "../prf.h"
#include "helpers.h"

#include <array>
#include <fstream>
#include <iostream>

int main(int argc, char** argv)
{
  if (argc != 3)
  {
    std::cout << argv[0] << " challenge solution" << std::endl;
    return -1;
  }

  std::ifstream ifs_input(argv[1]), ifs_expected(argv[2]);
  if (!ifs_input || !ifs_expected)
  {
    std::cout << "Unable to open input files." << std::endl;
    return -1;
  }

  std::array<uint8_t, 16> prf_key, prf_seed;
  read(ifs_input, prf_key);

  for (std::size_t s = 0; s != prf_seed.size(); ++s)
    prf_seed[s] = 0xff - s;

  hmac_prf prf(prf_key.data(), prf_key.size(), "ITS test cases", prf_seed.data(), prf_seed.size());

  ascon128::key_storage ascon_key;
  prf.get_output(ascon_key.data(), ascon_key.size());

  std::array<uint8_t, incrementing_nonce::fixed_common_size> nonce_fixed_common;
  std::array<uint8_t, incrementing_nonce::fixed_distinct_size> nonce_fixed_disctinct;

  prf.get_output(nonce_fixed_common.data(), nonce_fixed_common.size());
  read(ifs_input, nonce_fixed_disctinct);

  incrementing_nonce nonce(nonce_fixed_common.data(), nonce_fixed_disctinct.data());
  tls12_ascon tls(ascon_key, nonce);

  for (std::size_t s = 0; s != 5; ++s)
  {
    uint64_t sequence_number;
    ifs_input.read(reinterpret_cast<char*>(&sequence_number), sizeof(sequence_number));

    uint16_t plaintext_size = 0;
    ifs_input.read(reinterpret_cast<char*>(&plaintext_size), sizeof(plaintext_size));

    std::vector<uint8_t> plaintext(plaintext_size, 0);
    read(ifs_input, plaintext);

    tls12_ascon::record expected_record;
    ifs_expected.read(reinterpret_cast<char*>(&expected_record.header),
                      sizeof(expected_record.header));
    read(ifs_expected, expected_record.explicit_nonce);

    expected_record.ciphertext.resize(ntoh(expected_record.header.length) -
                                      expected_record.explicit_nonce.size());
    read(ifs_expected, expected_record.ciphertext);

    if (!ifs_input || !ifs_expected)
    {
      std::cout << "Failed to read data." << std::endl;
      return -1;
    }

    const auto actual_record = tls.encrypt(sequence_number, plaintext);

    if (actual_record != expected_record)
    {
      std::cout << "Records do not match." << std::endl;
      return -1;
    }

    std::vector<uint8_t> decrypted_plaintext;
    if (!tls.decrypt(sequence_number, actual_record, decrypted_plaintext))
    {
      std::cout << "Decryption failed." << std::endl;
      return -1;
    }

    if (plaintext.size() != decrypted_plaintext.size() || !std::equal(plaintext.begin(), plaintext.end(), decrypted_plaintext.begin()))
    {
      std::cout << "Plaintexts do not match." << std::endl;
      return -1;
    }
  }
}
