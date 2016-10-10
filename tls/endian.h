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

#ifndef ENDIAN_H
#define ENDIAN_H

#include <cstdint>

namespace detail
{
  template <class T>
  struct endian_info;

  template <>
  struct endian_info<uint8_t>
  {
    static constexpr uint8_t swap(uint8_t v)
    {
      return v;
    }
  };

  template <>
  struct endian_info<uint16_t>
  {
    static constexpr uint16_t swap(uint16_t v)
    {
      return __builtin_bswap16(v);
    }
  };

  template <>
  struct endian_info<uint32_t>
  {
    static constexpr uint32_t swap(uint32_t v)
    {
      return __builtin_bswap32(v);
    }
  };

  template <>
  struct endian_info<uint64_t>
  {
    static constexpr uint64_t swap(uint64_t v)
    {
      return __builtin_bswap64(v);
    }
  };
}

/// Swap byte values of an integer.
template <class T>
constexpr T byte_swap(T value)
{
  return detail::endian_info<T>::swap(value);
}

/// Convert integer from host byte order to little endian.
template <class T>
constexpr T htol(T value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return value;
#else
  return byte_swap(value);
#endif
}

/// Convert integer from from little endian to host byte order.
template <class T>
constexpr T ltoh(T value)
{
  return htol(value);
}

/// Convert integer from host byte order to big endian.
template <class T>
constexpr T htob(T value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return byte_swap(value);
#else
  return value;
#endif
}

/// Convert integer from from big endian to host byte order.
template <class T>
constexpr T btoh(T value)
{
  return htob(value);
}

/// Convert integer from host byte order to network byte order.
template <class T>
constexpr T hton(T value)
{
  return htob(value);
}

/// Convert integer from network byte order to host byte order.
template <class T>
constexpr T ntoh(T value)
{
  return hton(value);
}

#endif
