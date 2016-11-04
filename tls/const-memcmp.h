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

#ifndef CONST_MEMCMP_H
#define CONST_MEMCMP_H

#include <cstddef>

/// Compare two memory blocks of the same size using a constant time
/// comparison algorithm.
///
/// \param s1 first memory location
/// \param s2 second memory location
/// \param size size of s1 and s2
/// \returns 0 if both blocks are the same, non-0 otherwise
int const_memcmp(const void* s1, const void* s2, std::size_t size);

#endif
