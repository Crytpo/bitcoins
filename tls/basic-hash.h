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

#ifndef BASIC_HASH_H
#define BASIC_HASH_H

#include <array>
#include <cstddef>
#include <cstdint>

template <std::size_t B, std::size_t D>
struct basic_hash
{
  static constexpr std::size_t block_size  = B;
  static constexpr std::size_t digest_size = D;

  typedef std::array<uint8_t, digest_size> digest_storage;
};

#endif
