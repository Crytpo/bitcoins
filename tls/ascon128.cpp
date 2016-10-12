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

#include "ascon128.h"
#include "ascon/crypto_aead.h"

ascon128::ascon128()
{
  // \todo initialize
}

ascon128::ascon128(const key_storage& key)
{
  // \todo initialize with given key
}

void ascon128::set_key(const key_storage& key)
{
  // \todo store key
}

void ascon128::encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
                       const nonce_storage& nonce,
                       const std::vector<uint8_t>& additional_data) const
{
  // \todo perform encryption with Ascon with given data
}

bool ascon128::decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
                       const nonce_storage& nonce,
                       const std::vector<uint8_t>& additional_data) const
{
  // \todo perform decryption with Ascon with given data. If decryption is
  // successful return true, otherwise return false.
  return false;
}
