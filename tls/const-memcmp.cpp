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

#include "const-memcmp.h"
#include <cstdint>

int const_memcmp(const void* s1, const void* s2, std::size_t n)
{
  const uint8_t* u1 = static_cast<const uint8_t*>(s1);
  const uint8_t* u2 = static_cast<const uint8_t*>(s2);

  uint8_t r = 0;
  for (; n; ++u1, ++u2, --n)
    r |= *u1 ^ *u2;

  return r;
}
