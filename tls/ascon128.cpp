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

#include "ascon128.h"
#include "ascon/crypto_aead.h"
#include "random.h"

ascon128::ascon128()
{
  // no key specified -> use random key
  get_random_data(key_.data(), key_.size());
}

ascon128::ascon128(const key_storage& key)
{
  key_ = key;
}

void ascon128::set_key(const key_storage& key)
{
  key_ = key;
}

void ascon128::encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
                       const nonce_storage& nonce,
                       const std::vector<uint8_t>& additional_data) const
{
  // simply encrypt using the provided function
  unsigned long long clen;
  ciphertext.resize(ciphertext_size(plaintext.size()));

  crypto_aead_encrypt(ciphertext.data(), &clen,       // c, clen
      plaintext.data(), plaintext.size(),             // m, mlen
      additional_data.data(), additional_data.size(), // ad, adlen
      NULL,                                           // nsec (not used)
      nonce.data(),                                   // npub
      key_.data());                                   // k
}

bool ascon128::decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
                       const nonce_storage& nonce,
                       const std::vector<uint8_t>& additional_data) const
{
  // simply decrypt using the provided function
  unsigned long long mlen;
  plaintext.resize(plaintext_size(ciphertext.size()));

  int fail = crypto_aead_decrypt(plaintext.data(), &mlen,   // m, mlen
      NULL,                                                 // nsec (not used)
      ciphertext.data(), ciphertext.size(),                 // c, clen
      additional_data.data(), additional_data.size(),       // ad, adlen
      nonce.data(),                                         // npub
      key_.data());                                         // k

  if (fail != 0)
    return false;

  return true;
}
