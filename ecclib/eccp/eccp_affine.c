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

#include "eccp_affine.h"
#include "../gfp/gfp.h"
#include <string.h>

/**
 * Clear an ECC point
 * @param A point to clear
 */
void eccp_affine_point_clear(eccp_point_affine_t* A)
{
  if (A)
  {
    memset(A, 0x00, sizeof(eccp_point_affine_t));
  }
}

/**
 * Tests if the given affine point fulfills the elliptic curve equation.
 * (Does not perform a cofactor multiplication to check the order of the given
 * point.)
 * @param A point to test
 * @param param elliptic curve parameters
 * @return 1 if point is valid, otherwise 0
 */
int eccp_affine_point_is_valid(const eccp_point_affine_t* A, const eccp_parameters_t* param)
{
  gfp_t left, right;

  if (A->identity == 1)
    return 1;
  if (bigint_compare_var(A->x, param->prime_data.prime, param->prime_data.words) >= 0)
    return 0;
  if (bigint_compare_var(A->y, param->prime_data.prime, param->prime_data.words) >= 0)
    return 0;

  /* calculate the right side */
  /* use left as additional temp */
  gfp_square(left, A->x);
  gfp_multiply(right, A->x, left);          /* x^3 */
  gfp_multiply(left, A->x, param->param_a); /* a*x */
  gfp_add(right, right, left);              /* x^3 + a*x */
  gfp_add(right, right, param->param_b);    /* x^3 + a*x + b */

  /* calculate the left side */
  gfp_square(left, A->y);

  /* check if y^2 == x^3 + a*x + b */
  if (gfp_compare(left, right) == 0)
    return 1;
  else
    return 0;
}

/**
 *  Compares the two given points for equality. (identity is smaller, the compare x and y
 * coordinates)
 *  @param A
 *  @param B
 *  @param param elliptic curve parameters
 *  @return -1 if A is smaller, 0 if equal, 1 if A is larger.
 */
int eccp_affine_point_compare(const eccp_point_affine_t* A, const eccp_point_affine_t* B,
                              const eccp_parameters_t* param)
{
  int compare;
  if (A->identity == 1)
  {
    if (B->identity == 1)
      return 0;
    else
      return -1;
  }
  if (B->identity == 1)
    return 1;
  compare = gfp_compare(A->x, B->x);
  if (compare != 0)
  {
    return compare;
  }
  else
  {
    return gfp_compare(A->y, B->y);
  }
}

/**
 *  Copies an affine elliptic curve point.
 *  @param res the destination memory
 *  @param src the source memory
 *  @param param elliptic curve parameters
 */
void eccp_affine_point_copy(eccp_point_affine_t* dest, const eccp_point_affine_t* src,
                            const eccp_parameters_t* param)
{
  dest->identity = src->identity;
  gfp_copy(dest->x, src->x);
  gfp_copy(dest->y, src->y);
}

/**
 * Adds two affine points. Handles the case of R=A and R=B.
 * @param res
 * @param A
 * @param B
 * @param param elliptic curve parameters
 */
void eccp_affine_point_add(eccp_point_affine_t* res, const eccp_point_affine_t* A,
                           const eccp_point_affine_t* B, const eccp_parameters_t* param)
{
  gfp_t lambda, temp1, temp2;

  if (A->identity == 1)
  {
    eccp_affine_point_copy(res, B, param);
    return;
  }
  if (B->identity == 1)
  {
    eccp_affine_point_copy(res, A, param);
    return;
  }
  if (gfp_compare(A->x, B->x) == 0)
  {
    if (gfp_compare(A->y, B->y) == 0)
    {
      // CASE: A is equal to B
      eccp_affine_point_double(res, A, param);
      return;
    }
    else
    {
      // CASE: -A is equal to B
      // NOTE: There are only two possible values for y per x coordinate.
      res->identity = 1;
      return;
    }
  }

  gfp_subtract(temp2, B->x, A->x);
  gfp_inverse(temp1, temp2);
  gfp_subtract(temp2, B->y, A->y);
  gfp_multiply(lambda, temp1, temp2); // (y2-y1) / (x2-x1)
  gfp_square(temp1, lambda);
  gfp_subtract(temp1, temp1, A->x);
  gfp_subtract(temp1, temp1, B->x); // L^2 - x1 - x2
  gfp_subtract(temp2, A->x, temp1); // (x1 - x3)
  gfp_copy(res->x, temp1);
  gfp_multiply(temp1, temp2, lambda);
  gfp_subtract(res->y, temp1, A->y); // L*(x1-x3)-y1
  res->identity = 0;
}

/**
 * Doubles an affine point. Handles the case of R=A.
 * @param res
 * @param A
 * @param param elliptic curve parameters
 */
void eccp_affine_point_double(eccp_point_affine_t* res, const eccp_point_affine_t* A,
                              const eccp_parameters_t* param)
{
  gfp_t temp1, temp2, temp3;

  if (A->identity == 1)
  {
    res->identity = 1;
    return;
  }
  gfp_negate(temp1, A->y);
  if (gfp_compare(temp1, A->y) == 0)
  {
    // this handles the special case of doubling a point of order 2
    res->identity = 1;
    return;
  }

  gfp_add(temp1, A->y, A->y);
  gfp_inverse(temp2, temp1);
  gfp_square(temp1, A->x);
  gfp_add(temp3, temp1, temp1);
  gfp_add(temp3, temp3, temp1);          // 3*x1^2
  gfp_add(temp3, temp3, param->param_a); // 3*x1^2 + a
  gfp_multiply(temp1, temp2, temp3);     // lambda
  gfp_square(temp3, temp1);
  gfp_subtract(temp2, temp3, A->x);
  gfp_subtract(temp2, temp2, A->x); // x3 = L^2 - 2*x1
  gfp_subtract(temp3, A->x, temp2);
  gfp_copy(res->x, temp2);
  gfp_multiply(temp2, temp1, temp3);
  gfp_subtract(res->y, temp2, A->y); // y3 = L * (x1-x3) - y1
  res->identity = 0;
}

/**
 * Negates the given affine point.
 * @param res the resulting point (-P)
 * @param P the point to negate
 * @param param elliptic curve parameters
 */
void eccp_affine_point_negate(eccp_point_affine_t* res, const eccp_point_affine_t* P,
                              const eccp_parameters_t* param)
{
  gfp_copy(res->x, P->x);
  gfp_negate(res->y, P->y);
  res->identity = P->identity;
}
