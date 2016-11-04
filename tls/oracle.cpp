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

#include "oracle.h"

oracle::~oracle()
{
}

// local oracle

local_oracle::local_oracle(const ciphersuite::block_cipher_key& key,
                           const ciphersuite::hmac_key& hmac_key, clock_type ct)
  : ciphersuite_(key, hmac_key), ct_(ct)
{
}

local_oracle::~local_oracle()
{
}

std::pair<bool, uint64_t> local_oracle::decrypt(const record& record)
{
  std::vector<uint8_t> plaintext;

  uint64_t begin = 0;
  switch (ct_)
  {
  case RDTSC:
    begin = tsc_clock.begin();
    break;
  }

  const bool ret = ciphersuite_.decrypt(record, plaintext);

  uint64_t end = 0;
  switch (ct_)
  {
  case RDTSC:
    end = tsc_clock.end();
    break;
  }

  return std::make_pair(ret, end - begin);
}

oracle::record local_oracle::request_challenge(uint16_t size)
{
  std::vector<uint8_t> plaintext(size);
  return ciphersuite_.encrypt(plaintext.data(), plaintext.size());
};

oracle::record local_oracle::request_ciphertext()
{
  // not used
  return record();
}
