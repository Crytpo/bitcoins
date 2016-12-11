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

#ifndef GFP_MONT_H_
#define GFP_MONT_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

void gfp_normal_to_montgomery(gfp_t res, const gfp_t src, const gfp_prime_data_t* prime_data);
void gfp_montgomery_to_normal(gfp_t res, const gfp_t src, const gfp_prime_data_t* prime_data);

void gfp_mont_compute_R(gfp_t res, gfp_prime_data_t* prime_data);
void gfp_mont_compute_R_squared(gfp_t res, gfp_prime_data_t* prime_data);
void gfp_mont_compute_n(gfp_prime_data_t* prime_data);
uint_t gfp_mont_compute_n0(const gfp_prime_data_t* prime_data);
void gfp_mont_inverse(gfp_t result, const gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_mont_exponent(gfp_t res, const gfp_t a, const uint_t* exponent, const int exponent_length,
                       const gfp_prime_data_t* prime_data);

void gfp_mont_multiply(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data);
void gfp_mult_two_mont(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data);
void gfp_mont_sqrt(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_mont_square(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data);

#ifdef __cplusplus
}
#endif

#endif /* GFP_MONT_H_ */
