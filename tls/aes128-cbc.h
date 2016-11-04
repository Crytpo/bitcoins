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

#ifndef AES128_CBC_H
#define AES128_CBC_H

#include "aes128.h"
#include <cstdint>
#include <array>

/// Class implementing AES-CBC for AES with 128 bit keys.
class aes128_cbc
{
public:
  static constexpr std::size_t block_size = aes128::block_size;
  static constexpr std::size_t key_size   = aes128::key_size;
  static constexpr std::size_t iv_size    = block_size;

  typedef std::array<uint8_t, block_size> block_storage;

private:
  aes128 aes_;
  block_storage iv_;

public:
  /// Initialize without key and IV.
  aes128_cbc();

  /// Initialize with the given key and IV.
  aes128_cbc(const uint8_t* key, const uint8_t* iv);

  /// Set key.
  void set_key(const uint8_t* key);
  /// Set IV.
  void set_iv(const uint8_t* iv);

  /// Encrypt src of length size and store it in dst.
  ///
  /// \param dst target storage, must be at least size bytes large
  /// \param src plaintext to be encrypted
  /// \param size size of src, must be divisible by block_size
  void encrypt(uint8_t* dst, const uint8_t* src, std::size_t size);
  /// Decrypt src of length size and store it in dst.
  ///
  /// \param dst target storage, must be at least size bytes large
  /// \param src ciphertext to be decrypted
  /// \param size size of src, must be divisible by block_size
  void decrypt(uint8_t* dst, const uint8_t* src, std::size_t size);
};
#endif
