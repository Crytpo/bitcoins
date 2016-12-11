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

#include "param.h"
#include "../bi/bi.h"
#include "../eccp/eccp.h"
#include "../gfp/gfp.h"

#include <string.h>

const char* curve_names[] = CURVE_NAMES;

static const uint_t SECP256R1_COFACTOR  = 1;
static const uint_t SECP256R1_BASE_X[8] = {0x18A9143C, 0x79E730D4, 0x5FEDB601, 0x75BA95FC,
                                           0x77622510, 0x79FB732B, 0xA53755C6, 0x18905F76};
static const uint_t SECP256R1_BASE_Y[8] = {0xCE95560A, 0xDDF25357, 0xBA19E45C, 0x8B4AB8E4,
                                           0xDD21F325, 0xD2E88688, 0x25885D85, 0x8571FF18};
static const uint_t SECP256R1_A[8] = {0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000003,
                                      0x00000000, 0x00000000, 0x00000004, 0xFFFFFFFC};
static const uint_t SECP256R1_B[8] = {0x29C4BDDF, 0xD89CDF62, 0x78843090, 0xACF005CD,
                                      0xF7212ED6, 0xE5A220AB, 0x04874834, 0xDC30061D};
static const uint_t SECP256R1_ORDER_N_BITS = 256;
static const uint_t SECP256R1_PRIME_BITS   = 256;
static const uint_t SECP256R1_ORDER_N[8]   = {0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
                                            0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF};
static const uint_t SECP256R1_PRIME[8] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                                          0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF};
/**
 * Loads parameters for a given type of curve and stores them
 * into the structure referenced by param.
 * @param param the structure that is filled with elliptic curve parameters
 * @param type the type of curve to be used
 */
void param_load(eccp_parameters_t* param, const curve_type_t type)
{
  param->curve_type = type;
  param->eccp_mul   = &eccp_jacobian_point_multiply_L2R_DA;

  if (type == SECP256R1)
  {
    int bi_length = WORDS_PER_BITS(SECP256R1_PRIME_BITS);

    // set prime data
    param->prime_data.bits              = SECP256R1_PRIME_BITS;
    param->prime_data.words             = bi_length;
    param->prime_data.montgomery_domain = 1;
    bigint_copy_var(param->prime_data.prime, SECP256R1_PRIME, param->prime_data.words);

    // compute Montgomery constants
    gfp_mont_compute_R(param->prime_data.gfp_one, &(param->prime_data));
    gfp_mont_compute_R_squared(param->prime_data.r_squared, &(param->prime_data));
    gfp_mont_compute_n(&(param->prime_data));
    param->prime_data.n0 = gfp_mont_compute_n0(&(param->prime_data));

    // set prime data (group order)
    param->order_n_data.bits              = SECP256R1_ORDER_N_BITS;
    param->order_n_data.words             = WORDS_PER_BITS(SECP256R1_ORDER_N_BITS);
    param->order_n_data.montgomery_domain = 0;
    bigint_copy_var(param->order_n_data.prime, SECP256R1_ORDER_N, param->order_n_data.words);

    // compute Montgomery constants (group order)
    gfp_mont_compute_R(param->order_n_data.gfp_one, &(param->order_n_data));
    gfp_mont_compute_R_squared(param->order_n_data.r_squared, &(param->order_n_data));
    gfp_mont_compute_n(&(param->order_n_data));
    param->order_n_data.n0 = gfp_mont_compute_n0(&(param->order_n_data));

    // copy ECC parameters a, b, and cofactor h
    bigint_copy_var(param->param_a, SECP256R1_A, bi_length);
    bigint_copy_var(param->param_b, SECP256R1_B, bi_length);
    param->h = SECP256R1_COFACTOR;

    // copy ECC base point
    bigint_copy_var(param->base_point.x, SECP256R1_BASE_X, bi_length);
    bigint_copy_var(param->base_point.y, SECP256R1_BASE_Y, bi_length);
    param->base_point.identity = 0;
  }
}
