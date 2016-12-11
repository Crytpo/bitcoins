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

#ifndef ECDSA_H_
#define ECDSA_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

void ecdsa_sign(ecdsa_signature_t* signature, const gfp_t hash_of_message, const gfp_t private_key,
                const eccp_parameters_t* param);
int ecdsa_is_valid(const ecdsa_signature_t* signature, const gfp_t hash_of_message,
                   const eccp_point_affine_t* public_key, const eccp_parameters_t* param);

void ecdsa_hash_to_gfp(gfp_t element, const uint8_t* hash, const int hash_length,
                       const gfp_prime_data_t* prime);

#ifdef __cplusplus
}
#endif

#endif /* ECDSA_H_ */
