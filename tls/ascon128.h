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

#ifndef ASCON128_H
#define ASCON128_H

#include <array>
#include <vector>

#include "ascon/api.h"
#include "basic-ae.h"

/// ASCON with 128 bit keys.
class ascon128 : private basic_ae<CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, CRYPTO_ABYTES>
{
public:
  typedef basic_ae<CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, CRYPTO_ABYTES> base;

  using base::additional_size;
  using base::key_size;
  using base::nonce_size;

  typedef std::array<uint8_t, key_size> key_storage;
  typedef std::array<uint8_t, nonce_size> nonce_storage;

private:
  key_storage key_;

public:
  /// Initialize
  ascon128();
  /// Initialize with given key.
  ///
  /// \param key 128 bit key
  ascon128(const key_storage& key);

  /// Set up key for encryption and decryption.
  ///
  /// \param key 128 bit key
  void set_key(const key_storage& key);

  void encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
               const nonce_storage& nonce,
               const std::vector<uint8_t>& additional_data = std::vector<uint8_t>()) const;

  bool decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
               const nonce_storage& nonce,
               const std::vector<uint8_t>& additional_data = std::vector<uint8_t>()) const;

  static std::size_t ciphertext_size(const std::size_t size)
  {
    return size + additional_size;
  }

  static std::size_t plaintext_size(const std::size_t size)
  {
    return size - additional_size;
  }
};

#endif
