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

#include "sha1.h"
#include "endian.h"
#include "misc.h"

#include <cstring>

namespace
{
  constexpr uint32_t round_constants[] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

  constexpr uint8_t pad[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

void sha1::step()
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  for (auto& v : chunck_.b32)
    v = byte_swap(v);
#endif

  uint32_t a = digest_.b32[0];
  uint32_t b = digest_.b32[1];
  uint32_t c = digest_.b32[2];
  uint32_t d = digest_.b32[3];
  uint32_t e = digest_.b32[4];

  for (std::size_t t = 0; t != 80; ++t)
  {
    const std::size_t s = t & 0x0f;

    if (t >= 16)
      chunck_.b32[s] = rotate(chunck_.b32[(s + 13) & 0x0f] ^ chunck_.b32[(s + 8) & 0x0f] ^
                                  chunck_.b32[(s + 2) & 0x0f] ^ chunck_.b32[s],
                              1);

    uint32_t f = e + round_constants[t / 20] + chunck_.b32[s];
    if (t < 20)
      f += (b & c) | ((~b) & d);
    else if (t < 40 || t >= 60)
      f += b ^ c ^ d;
    else if (t < 60)
      f += (b & c) | (b & d) | (c & d);

    e = d;
    d = c;
    c = rotate(b, 30);
    b = a;
    a = rotate(a, 5) + f;
  }

  digest_.b32[0] += a;
  digest_.b32[1] += b;
  digest_.b32[2] += c;
  digest_.b32[3] += d;
  digest_.b32[4] += e;
}

/*------------------------------------------------------------*/

sha1::sha1()
  : chunck_{{0}}, digest_{{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}}, counter_(0)
{
}

void sha1::update(const uint8_t* data, std::size_t len)
{
  std::size_t off = 0;
  while (off < len)
  {
    const std::size_t gap_start  = counter_ % block_size;
    const std::size_t gap_length = block_size - gap_start;
    const std::size_t copy_size  = std::min(gap_length, len - off);

    std::memcpy(&chunck_.b8[gap_start], &data[off], copy_size);
    counter_ += copy_size;
    off += copy_size;

    if (counter_ % block_size == 0)
      step();
  }
}

sha1::digest_storage sha1::digest()
{
  const uint64_t message_length = htob(counter_ * 8);

  const std::size_t gap_start = counter_ % block_size;
  const std::size_t gap_size  = block_size - gap_start;
  if (gap_size > sizeof(uint64_t))
    std::memcpy(&chunck_.b8[gap_start], pad, gap_size - sizeof(uint64_t));
  else
  {
    std::memcpy(&chunck_.b8[gap_start], pad, gap_size);
    step();
    std::memcpy(chunck_.b8, &pad[gap_size], block_size - sizeof(uint64_t));
  }

  std::memcpy(&chunck_.b8[block_size - sizeof(uint64_t)], &message_length, sizeof(uint64_t));
  step();

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  for (auto& v : digest_.b32)
    v = byte_swap(v);
#endif

  digest_storage result;
  std::memcpy(result.data(), &digest_.b8[0], digest_size);
  return result;
}
