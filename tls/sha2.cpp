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

#include "sha2.h"
#include "endian.h"
#include "misc.h"

#include <cstring>

namespace
{
  constexpr uint32_t round_constants[] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2};

  constexpr uint8_t pad[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

void sha2::step()
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  for (auto& v : chunck_.b32)
    v = byte_swap(v);
#endif

  std::array<uint32_t, digest_size / sizeof(uint32_t)> S;
  std::array<uint32_t, block_size> W;

  std::copy(std::begin(digest_.b32), std::end(digest_.b32), S.begin());
  std::copy(std::begin(chunck_.b32), std::end(chunck_.b32), W.begin());

  for (std::size_t t = 16; t != W.size(); ++t)
  {
    const auto s0 = right_rotate(W[t - 15], 7) ^ right_rotate(W[t - 15], 18) ^ (W[t - 15] >> 3);
    const auto s1 = right_rotate(W[t - 2], 17) ^ right_rotate(W[t - 2], 19) ^ (W[t - 2] >> 10);
    W[t]          = W[t - 16] + s0 + W[t - 7] + s1;
  }

  for (std::size_t t = 0; t != 64; ++t)
  {
    const auto s1    = right_rotate(S[4], 6) ^ right_rotate(S[4], 11) ^ right_rotate(S[4], 25);
    const auto ch    = (S[4] & S[5]) ^ (~S[4] & S[6]);
    const auto temp1 = S[7] + s1 + ch + round_constants[t] + W[t];
    const auto s0    = right_rotate(S[0], 2) ^ right_rotate(S[0], 13) ^ right_rotate(S[0], 22);
    const auto maj   = (S[0] & S[1]) ^ (S[0] & S[2]) ^ (S[1] & S[2]);
    const auto temp2 = s0 + maj;

    S[7] = S[6];
    S[6] = S[5];
    S[5] = S[4];
    S[4] = S[3] + temp1;
    S[3] = S[2];
    S[2] = S[1];
    S[1] = S[0];
    S[0] = temp1 + temp2;
  }

  for (std::size_t t = 0; t != digest_size / sizeof(uint32_t); ++t)
    digest_.b32[t] += S[t];
}

/*------------------------------------------------------------*/

sha2::sha2()
  : chunck_{{0}}, digest_{{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                           0x1f83d9ab, 0x5be0cd19}},
    counter_(0)
{
}

void sha2::update(const uint8_t* data, std::size_t len)
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

sha2::digest_storage sha2::digest()
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
