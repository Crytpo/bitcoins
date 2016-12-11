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

#ifndef GFP_GEN_H_
#define GFP_GEN_H_

#include "../types.h"

#include "../bi/bi.h"

#ifdef __cplusplus
extern "C" {
#endif

void gfp_gen_add(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data);
void gfp_gen_subtract(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data);
void gfp_gen_halving(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_gen_negate(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_gen_multiply_div(gfp_t res, const gfp_t a, const gfp_t b,
                          const gfp_prime_data_t* prime_data);
void gfp_reduce(gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_binary_euclidean_inverse(gfp_t result, const gfp_t to_invert,
                                  const gfp_prime_data_t* prime_data);

#ifdef __cplusplus
}
#endif

#endif /* GFP_GEN_H_ */
