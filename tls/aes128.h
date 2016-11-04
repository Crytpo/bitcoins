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

#ifndef AES128_H
#define AES128_H

#include "basic-block-cipher.h"
#include <array>

#ifdef HAVE_AESNI
#include <wmmintrin.h>
#endif

/// AES with 128 bit keys.
class aes128 : private basic_block_cipher<16, 16>
{
public:
  typedef basic_block_cipher<16, 16> base;
  typedef typename base::block_storage block_storage;

  using base::block_size;
  using base::key_size;

  static constexpr std::size_t rounds = 10;

  union key_storage {
#ifdef HAVE_AESNI
    __m128i m128is[rounds + 1] __attribute__((aligned(16)));
#endif
    std::array<uint32_t, 4 * (rounds + 1)> u32s;
  };

private:
  key_storage encryption_key_, decryption_key_;

  typedef void (*set_key_fn)(key_storage&, key_storage&, const uint8_t*);
  typedef void (*encrypt_fn)(const key_storage&, uint8_t*, const uint8_t*);
  typedef void (*decrypt_fn)(const key_storage&, uint8_t*, const uint8_t*);

  static set_key_fn set_key_impl;
  static encrypt_fn encrypt_impl;
  static decrypt_fn decrypt_impl;

public:
  /// Initialize
  aes128();
  /// Initialize with given key.
  ///
  /// \param key 128 bit key
  aes128(const uint8_t* key);

  /// Set up key for encryption and decryption.
  ///
  /// \param key 128 bit key
  void set_key(const uint8_t* key);
  /// Encrypt one block.
  ///
  /// \param dst output block
  /// \param src input block
  void encrypt(uint8_t* dst, const uint8_t* src) const;
  /// Decrypt one block.
  ///
  /// \param dst output block
  /// \param src input block
  void decrypt(uint8_t* dst, const uint8_t* src) const;

  void encrypt(block_storage& storage) const
  {
    encrypt(storage.block, storage.block);
  }

  void decrypt(block_storage& storage) const
  {
    decrypt(storage.block, storage.block);
  }
} __attribute__((aligned(16)));

#endif
