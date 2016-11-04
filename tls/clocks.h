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

#ifndef CLOCKS_H
#define CLOCKS_H

#include <cstdint>

/// "Clocks" for measuring the execution time. All of these classes need to have
/// two methods: begin() and end(). They are called at the beginning
/// respectively the end of a measurement and the difference should give the
/// time between to two calling locations.

/// A "clock" using RDTSC(P) instructions.
struct rdtsc_clock
{
  /// Start the measurement.
  ///
  /// \returns current value of TSC
  static uint64_t begin();
  /// End the measurement.
  ///
  /// \returns current value of TSC
  static uint64_t end();
};

#endif
