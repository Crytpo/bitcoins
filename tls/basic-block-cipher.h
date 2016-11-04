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

#ifndef BASIC_BLOCK_CIPHER_H
#define BASIC_BLOCK_CIPHER_H

#include <cstddef>
#include <cstdint>

template <std::size_t K, std::size_t B>
struct basic_block_cipher
{
  static constexpr std::size_t block_size = B;
  static constexpr std::size_t key_size   = K;

  struct block_storage
  {
    uint8_t block[block_size];
  };
};

#endif
