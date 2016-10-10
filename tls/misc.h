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

#ifndef MISC_H
#define MISC_H

#include <cstdint>

constexpr uint32_t rotate(uint32_t x, uint8_t c)
{
  return (x << c) | (x >> (32 - c));
}

constexpr uint32_t right_rotate(uint32_t x, uint8_t c)
{
  return (x >> c) | (x << (32 - c));
}

#endif
