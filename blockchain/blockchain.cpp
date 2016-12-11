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

#include "blockchain.h"

bool block_chain::add_block(const full_block& fb)
{
  /// \todo implement
  return false;
}

uint32_t block_chain::get_balance(const ecc_public_key_t& public_key) const
{
  /// \todo implement

  return 0;
}

const full_block& block_chain::operator[](std::size_t index) const
{
  /// \todo implement
}

std::size_t block_chain::size() const
{
  /// \todo implement

  return 0;
}
