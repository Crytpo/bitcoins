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

/**
 *  @file gfp.h
 *
 *  The following defines gfp_* are assuming that there exists a local
 *  variable ecc_parameters_t *param. The defines beautify the eccp code
 *  and make it easier to exchange underlying gfp_* functions.
 */

#ifndef GFP_H_
#define GFP_H_

#include "../bi/bi.h"
#include "gfp_gen.h"
#include "gfp_mont.h"

#ifdef __cplusplus
extern "C" {
#endif

#define gfp_add(res, a, b) gfp_gen_add(res, a, b, &param->prime_data)
#define gfp_subtract(res, a, b) gfp_gen_subtract(res, a, b, &param->prime_data)
#define gfp_halving(res, a) gfp_gen_halving(res, a, &param->prime_data)
#define gfp_negate(res, a) gfp_gen_negate(res, a, &param->prime_data)
#define gfp_multiply(res, a, b) gfp_mont_multiply(res, a, b, &param->prime_data)
#define gfp_square(res, a) gfp_mont_multiply(res, a, a, &param->prime_data)
#define gfp_inverse(res, a) gfp_mont_inverse(res, a, &param->prime_data)
#define gfp_exponent(res, a, exponent, exponent_length)                                            \
  gfp_mont_exponent(res, a, exponent, exponent_length, &param->prime_data)

#define gfp_clear(dest) bigint_clear_var(dest, WORDS_PER_GFP)
#define gfp_copy(dest, src) bigint_copy_var(dest, src, param->prime_data.words)
#define gfp_compare(a, b) bigint_compare_var(a, b, param->prime_data.words)
#define gfp_is_zero(a) bigint_is_zero_var(a, param->prime_data.words)

// #define gfp_compare(a,b,prime_data)
// bigint_compare_var(a,b,(prime_data)->words)

#ifdef __cplusplus
}
#endif
#endif /* GFP_H_ */
