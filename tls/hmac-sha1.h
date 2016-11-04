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

#ifndef HMAC_SHA1_H
#define HMAC_SHA1_H

#include "sha1.h"

#include <array>
#include <cstdint>

/// HMAC using SHA1
///
/// This class is intended to be used in the following way:
///
/// * Initialize on construction with the key.
/// * Call update as long as data should be feed to the HMAC. Note that the
///   message can be given in full using one call to update or by calling update
///   multiple times with consecutive parts of the message.
/// * Call digest to get the HMAC.
///
/// In the following example, both instances produce the same HMAC:
/// \code
/// uint8_t data[data_size]; // assume data_size % 2 == 0
/// hmac_sha1 h1(key, key_size), h2(key, key_size);
/// h1.update(data, data_size);
/// h2.update(data, data_size / 2);
/// h2.update(data + data_size / 2, data_size / 2)
/// const auto d1 = h1.digest(), d2 = h2.digest();
/// assert(memcmp(d1.data(), d2.data(), digest_size) == 0);
/// \endcode
class hmac_sha1
{
public:
  typedef sha1 hash;

private:
  hash ctx_i_;
  hash ctx_o_;

public:
  /// Size (in bytes) of the digest.
  static constexpr std::size_t digest_size = hash::digest_size;
  /// Block size.
  static constexpr std::size_t block_size = hash::block_size;
  /// Array containing the digest.
  typedef hash::digest_storage digest_storage;

  /// Initialize with key of the given size.
  hmac_sha1(const uint8_t* key, std::size_t keysize);

  /// Feed data to the HMAC.
  void update(const uint8_t* bytes, std::size_t size);
  /// Compute the digest.
  digest_storage digest();
};

#endif
