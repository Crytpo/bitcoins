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

#ifndef HELPERS_H
#define HELPERS_H

#include <iomanip>
#include <sstream>
#include <string>
#include <fstream>
#include <array>
#include <vector>

namespace
{
  template <class T>
  std::string digest_to_string(const T& digest)
  {
    std::ostringstream oss;
    for (const auto v : digest)
      oss << std::setfill('0') << std::setw(2) << std::hex << (uint32_t)v;

    return oss.str();
  }

  template <class H>
  std::string compute_hash(const uint8_t* data, const std::size_t data_size,
                           const std::size_t loops)
  {
    H hash;
    for (std::size_t l = 0; l < loops; ++l)
      hash.update(data, data_size);
    const auto digest = hash.digest();

    return digest_to_string(digest);
  }

  template <class H>
  std::string compute_hmac(const uint8_t* key, std::size_t key_size, const uint8_t* data,
                           const std::size_t data_size)
  {
    H hmac(key, key_size);
    hmac.update(data, data_size);
    const auto digest = hmac.digest();

    return digest_to_string(digest);
  }

  template <class H>
  std::string compute_hmac_i(const uint8_t* key, std::size_t key_size, const uint8_t* data,
                             const std::size_t data_size)
  {
    H hmac(key, key_size);
    for (std::size_t idx = 0; idx != data_size; ++idx, ++data)
      hmac.update(data, 1);
    const auto digest = hmac.digest();

    return digest_to_string(digest);
  }

  template <class T, std::size_t S>
  void read(std::istream& is, std::array<T, S>& array)
  {
    is.read(reinterpret_cast<char*>(array.data()), array.size());
  }

  template <class T>
  void read(std::istream& is, std::vector<T>& array)
  {
    is.read(reinterpret_cast<char*>(array.data()), array.size());
  }
}

#endif
