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

#include "prf.h"

// p(s, D) = HMAC(s, A_1 || D) || HMAC(s, A_2 || D) ...
// D = label || seed
// A_0 = D
// A_i = HMAC(s, A_i-1)
hmac_prf::hmac_prf(const uint8_t* secret, size_t secretlen,
    const std::string& label, const uint8_t* seed, size_t seedlen)
    : secret_(secret, secret + secretlen), current_position_(0)
{
  // calculate D, A_1 and save secret, which is needed for every part
  D_.resize(label.size() + seedlen);
  std::copy(label.data(), label.data() + label.size(), D_.data());
  std::copy(&seed[0], &seed[0] + seedlen, D_.data() + label.size());

  // calculate A_1
  hmac_sha2 hash_function(secret_.data(), secret_.size());
  hash_function.update(D_.data(), D_.size());
  A_ = hash_function.digest();
}

void hmac_prf::get_output(uint8_t* dst, size_t len)
{
  // append new HMAC values until desired length
  while ((current_position_ + len) > P_.size())
  {
    // resize P to also hold new data
    P_.resize(P_.size() + hmac_sha2::digest_size);

    // calculate new HMAC value using current A_i and D and the secret
    hmac_sha2 hash_function(secret_.data(), secret_.size());
    hash_function.update(A_.data(), A_.size());
    hash_function.update(D_.data(), D_.size());
    hmac_sha2::digest_storage new_hash_part = hash_function.digest();

    // append value to current P
    std::copy(new_hash_part.begin(), new_hash_part.end(),
        P_.end() - new_hash_part.size());

    // calculate next A_i
    hash_function = hmac_sha2(secret_.data(), secret_.size());
    hash_function.update(A_.data(), A_.size());
    A_ = hash_function.digest();
  }

  // copy length bytes from P to the destination and set position accordingly
  // for next function call
  std::copy(P_.begin() + current_position_, P_.begin() + current_position_ + len, dst);
  current_position_ = current_position_ + len;
}
