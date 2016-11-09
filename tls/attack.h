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

#ifndef ATTACK_H
#define ATTACK_H

#include <cstdint>
#include <vector>

#include "oracle.h"

/// Lucky13 attack using the RDTSC clock.
///
/// \param original_record ciphertext record
/// \param oracle decryption oracle
/// \return recovered plaintext
std::vector<uint8_t> lucky13_tsc(const oracle::record& original_record, local_oracle& oracle);

/// Lucky13 attack using the RDTSC clock.
///
/// \param original_record ciphertext record
/// \param oracle decryption oracle
/// \return recovered plaintext
std::vector<uint8_t> lucky13_tsc(const oracle::record& original_record, remote_oracle& oracle);

#endif
