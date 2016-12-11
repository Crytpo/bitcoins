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

#ifndef BLOCKCHAIN_ATTACK_H
#define BLOCKCHAIN_ATTACK_H

#include "blockchain.h"
#include "ecdsa.h"

/**
 * \brief Implements the attack on the KUcoin.
 *
 * First, the attack finds the user that created signatures while re-using the
 * ephemeral key. Then it creates blocks containing transactions that transfer
 * all unspent coins of the target user to the attacker.
 *
 * @param bc the blockchain
 * @param target_private_key recovered private key of the targeted user
 * @param target_public_key public key of the targeted user
 * @param attacker_private_key private key of the attacker
 * @param attacker_public_key public key of the attacker
 * @return true if the attack was successful, false otherwise
 */
bool attack(block_chain& bc, gfp_t& target_private_key, ecc_public_key_t& target_public_key, const gfp_t& attacker_private_key,
            const ecc_public_key_t& attacker_public_key);

#endif
