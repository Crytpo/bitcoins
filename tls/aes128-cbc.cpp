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

#include "aes128-cbc.h"
#include <cstring>

namespace
{
  template<class T, std::size_t S>
  std::array<T, S>& operator ^=(std::array<T, S>& a, const T* d)
  {
    for (std::size_t s = 0; s != S; ++s)
    {
      a[s] ^= d[s];
    }
    return a;
  }
}

aes128_cbc::aes128_cbc()
{
}

aes128_cbc::aes128_cbc(const uint8_t* key, const uint8_t* iv)
{
  set_key(key);
  set_iv(iv);
}

void aes128_cbc::set_key(const uint8_t* key)
{
  aes_.set_key(key);
}

void aes128_cbc::set_iv(const uint8_t* iv)
{
  std::memcpy(iv_.data(), iv, iv_size);
}

void aes128_cbc::encrypt(uint8_t* dst, const uint8_t* src, std::size_t size)
{
  for (std::size_t s = 0; s < size; s += block_size, dst += block_size, src += block_size)
  {
    iv_ ^= src;
    aes_.encrypt(iv_.data(), iv_.data());
    std::memcpy(dst, iv_.data(), block_size);
  }
}

void aes128_cbc::decrypt(uint8_t* dst, const uint8_t* src, std::size_t size)
{
  for (std::size_t s = 0; s < size; s += block_size, dst += block_size, src += block_size)
  {
    block_storage storage;
    aes_.decrypt(storage.data(), src);
    storage ^= iv_.data();
    std::memcpy(iv_.data(), src, block_size);
    std::memcpy(dst, storage.data(), block_size);
  }
}
