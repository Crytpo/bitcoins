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

#include "merkletree.h"

merkle_tree::merkle_tree(const std::vector<sha2::digest_storage>& hashes)
{
  /// \todo implement
}

merkle_tree::merkle_tree(const sha2::digest_storage& root_hash)
{
  /// \todo implement
}

std::vector<merkle_tree::proof_node> merkle_tree::proof(const sha2::digest_storage& value) const
{
  /// \todo implement

  return {};
}

bool merkle_tree::verify(const sha2::digest_storage& value,
                         const std::vector<proof_node>& proof) const
{
  /// \todo implement

  return false;
}

sha2::digest_storage merkle_tree::root_hash() const
{
  /// \todo implement

  return {};
}
