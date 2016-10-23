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

#include "random.h"
#include <fstream>

void get_random_data(uint8_t* data, std::size_t size)
{
  /*
   * NOTE: srand(time(0)) not secure because time is used as seed
   *       If attacker can guess the time -> easily crackable
   *       rand() implementations also platform specific and not secure
   *
   * /dev/random more secure but it blocks when entropy pool is empty,
   * /dev/urandom does not block, therefore it is theoretically vulnerable
   * to cryptoanalysis, but creates enough randomness for this task
  */

  std::ifstream random("/dev/urandom", std::ios::in | std::ios::binary);
  if (random.is_open())
  {
    random.read(reinterpret_cast<char*>(data), size);
    random.close();
  }
}
