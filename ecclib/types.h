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

#ifndef TYPES_H_
#define TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t uint_t;
typedef uint64_t ulong_t;
typedef int64_t slong_t;

#define UINT_T_MAX 0xFFFFFFFF

/** The number of bytes represented by a word. */
#define BYTES_PER_WORD 4
/** The number of bits represented by a word. */
#define BITS_PER_WORD (BYTES_PER_WORD << 3)
/** binary logarithm of BITS_PER_WORD*/
#define LD_BITS_PER_WORD 5
/** binary logarithm of BYTES_PER_WORD*/
#define LD_BYTES_PER_WORD 2
/** returns the number of words needed to store the defined number of bits */
#define WORDS_PER_BITS(bits) (((bits - 1) >> LD_BITS_PER_WORD) + 1)
/** returns the number of bytes needed to store the defined number of bits */
#define BYTES_PER_BITS(bits) (((bits - 1) >> 3) + 1)
/** the number of bits that has to fit within bigint_t */
#define MIN_BITS_PER_GFP 256
/** the number of words that fit within bigint_t */
#define WORDS_PER_GFP (WORDS_PER_BITS(MIN_BITS_PER_GFP))
#define WORDS_PER_BIGINT WORDS_PER_GFP
/** the number of bytes that fit within bigint_t */
#define BYTES_PER_GFP (WORDS_PER_GFP * BYTES_PER_WORD)
/** the number of bits that fit within bigint_t */
#define BITS_PER_GFP (WORDS_PER_GFP * BITS_PER_WORD)

/** Represent a number in GF(p) - same as bigint_t */
typedef uint_t gfp_t[WORDS_PER_GFP];
typedef gfp_t bigint_t; // alias to bigint when dealing with RSA

/** Set of parameters needed for general GF(p) operations.
 *  Includes a set of parameters needed for Montgomery GF(p) multiplications.
 *  R is assumed to be (1 << (words * BITS_PER_WORD)).
 */
typedef struct _prime_data_t_
{
  /** the prime number used for reduction */
  gfp_t prime;
  /** the number of bits needed to represent the prime */
  uint32_t bits;
  /** the number of words needed to represent the prime */
  uint32_t words;
  /** specifies whether computations are performed in
   * Montgomery domain using Montgomery multiplication*/
  uint8_t montgomery_domain;
  /** constant needed for Montgomery multiplication */
  uint_t prime_n[WORDS_PER_GFP];
  /** constant needed for optimized Montgomery multiplication */
  uint_t n0;
  /** R^2 to be used for Montgomery conversion */
  gfp_t r_squared;
  /** 1*R equals one */
  gfp_t gfp_one;
} prime_data_t;

typedef prime_data_t gfp_prime_data_t;

/** Elliptic curve point in affine coordinates. */
typedef struct _eccp_point_affine_t_
{
  gfp_t x;
  gfp_t y;
  uint8_t identity;
} eccp_point_affine_t;
/** Elliptic curve point using projective (x,y,z) coordinates. */
typedef struct _eccp_point_projective_t_
{
  gfp_t x;
  gfp_t y;
  gfp_t z;
  uint8_t identity;
} eccp_point_projective_t;
/** specifies the used eccp_parameters_t */

#define SECP256R1_NAME "secp256r1"
#define CUSTOM_NAME "custom"
#define UNKNOWN_NAME "unknown"

typedef enum _curve_type_t {
  UNKNOWN,
  SECP256R1,
  CUSTOM,
} curve_type_t;
#define CURVE_NAMES                                                                                \
  {                                                                                                \
    UNKNOWN_NAME, SECP256R1_NAME, CUSTOM_NAME                                                      \
  }

extern const char* curve_names[];

/** Parameters needed to do elliptic curve computations. */
struct _eccp_parameters_t_;
/** typedef of function pointer to an optimized eccp scalar multiplication (used in
 * eccp_parameters_t) */
typedef void (*eccp_mul_t)(eccp_point_affine_t*, const eccp_point_affine_t*, const gfp_t,
                           const struct _eccp_parameters_t_*);
/** typedef of function pointer to an optimized scalar multiplication with constant point (used in
 * eccp_parameters_t). */
typedef void (*eccp_mul_const_t)(eccp_point_affine_t*, const eccp_point_affine_t*,
                                 const unsigned int, const gfp_t,
                                 const struct _eccp_parameters_t_*);
/** Parameters needed to do elliptic curve computations. */
typedef struct _eccp_parameters_t_
{
  /** data needed to do computations modulo the prime */
  gfp_prime_data_t prime_data;
  /** data needed to do computations modulo the group order n */
  gfp_prime_data_t order_n_data;
  /** (cofactor h)*(order n) is the total number of points representable with
   * the equation y^2=x^3+ax+b */
  uint_t h;
  /** parameter a of the used elliptic curve y^2=x^3+ax+b */
  gfp_t param_a;
  /** parameter b of the used elliptic curve y^2=x^3+ax+b */
  gfp_t param_b;
  /** the standardized base point */
  eccp_point_affine_t base_point;
  /** specifies the used elliptic curve */
  curve_type_t curve_type;
  /** generic scalar multiplication to be used for protocols */
  eccp_mul_t eccp_mul;
} eccp_parameters_t;

/** ECDSA signature, with GF(p) elements modulo ecc_parameters_t.order_n_data */
typedef struct _ecdsa_signature_t_
{
  gfp_t r;
  gfp_t s;
} ecdsa_signature_t;

#ifdef __cplusplus
}
#endif
#endif /* TYPES_H_ */
