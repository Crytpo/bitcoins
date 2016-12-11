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

#ifndef UTILS_IO_H
#define UTILS_IO_H

#include <array>
#include <iosfwd>
#include <type_traits>
#include <vector>

namespace
{
  template <class T>
  void read(std::istream& is, T& u)
  {
    static_assert(std::is_integral<T>::value, "Integer required.");
    is.read(reinterpret_cast<char*>(&u), sizeof(u));
  }

  template <class T>
  void write(std::ostream& os, T u)
  {
    static_assert(std::is_integral<T>::value, "Integer required.");
    os.write(reinterpret_cast<const char*>(&u), sizeof(u));
  }

  template <class T, std::size_t S>
  void read(std::istream& is, T (&array)[S])
  {
    for (auto& val : array)
      read(is, val);
  }

  template <class T, std::size_t S>
  void write(std::ostream& os, const T (&array)[S])
  {
    for (const auto& val : array)
      write(os, val);
  }

  template <class T, std::size_t S>
  void read(std::istream& is, std::array<T, S>& array)
  {
    for (auto& val : array)
      read(is, val);
  }

  template <class T, std::size_t S>
  void write(std::ostream& os, const std::array<T, S>& array)
  {
    for (const auto& val : array)
      write(os, val);
  }

  template <class T>
  void read(std::istream& is, std::vector<T>& array, bool with_size = false)
  {
    if (with_size)
    {
      typename std::vector<T>::size_type size = 0;
      read(is, size);
      array.resize(size);
    }

    for (auto& val : array)
      read(is, val);
  }

  template <class T>
  void write(std::ostream& os, const std::vector<T>& array, bool with_size = false)
  {
    if (with_size)
      write(os, array.size());

    for (const auto& val : array)
      write(os, val);
  }
}

#endif
