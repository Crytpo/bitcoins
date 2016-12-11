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

#include "gfp_gen.h"
#include "../bi/bi.h"

/**
 * Adds two numbers a,b and stores the result in res. A finite field reduction
 * using modulo is automatically performed.
 * @param res the result
 * @param a the first parameter to add
 * @param b the second parameter to add
 * @param prime_data the prime number data to reduce the result
 */
void gfp_gen_add(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data)
{
  int carry = bigint_add_var(res, a, b, prime_data->words);
  if (carry)
  {
    bigint_subtract_var(res, res, prime_data->prime, prime_data->words);
  }
  else
  {
    if (bigint_compare_var(res, prime_data->prime, prime_data->words) >= 0)
    {
      bigint_subtract_var(res, res, prime_data->prime, prime_data->words);
    }
  }
}

/**
 * Subtract b from a, store it in res, use the modulo. res = (a - b) mod modulo.
 * @param a the minuend
 * @param b the subtrahend
 * @param res the difference
 * @param prime_data the prime number data to reduce the result
 */
void gfp_gen_subtract(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data)
{
  int carry = bigint_subtract_var(res, a, b, prime_data->words);
  if (carry)
  {
    bigint_add_var(res, res, prime_data->prime, prime_data->words);
  }
}

/**
 * divides a by two and stores the result in res
 * if number is even, divide by 2
 * if number is odd, add prime and divide by 2
 * @param res the result
 * @param a the operand to divide
 * @param prime_data the prime number data to reduce the result
 */
void gfp_gen_halving(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data)
{
  uint_t carry;
  if (BIGINT_IS_ODD(a))
  {
    carry = bigint_add_var(res, a, prime_data->prime, prime_data->words);
    bigint_shift_right_one_var(res, res, prime_data->words);
    res[prime_data->words - 1] |= carry << (BITS_PER_WORD - 1);
  }
  else
  {
    bigint_shift_right_one_var(res, a, prime_data->words);
  }
}

/**
 * Negate a element modulo p
 * @param a the gfp element to negate
 * @param res the negated element
 * @param prime_data the prime number data to reduce the result
 */
void gfp_gen_negate(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data)
{
  if (bigint_is_zero_var(a, prime_data->words))
  {
    bigint_copy_var(res, a, prime_data->words);
  }
  else
  {
    bigint_subtract_var(res, prime_data->prime, a, prime_data->words);
  }
}

/**
 * (Slow) Division based GF(p) multiplication.
 * @param res the product
 * @param a first operand
 * @param b second operand
 * @param prime_data the prime number data to reduce the result
 */
void gfp_gen_multiply_div(gfp_t res, const gfp_t a, const gfp_t b,
                          const gfp_prime_data_t* prime_data)
{
  uint_t product[2 * WORDS_PER_GFP] = {
      0,
  };
  uint_t extended_prime[2 * WORDS_PER_GFP] = {
      0,
  };
  uint_t quotient[2 * WORDS_PER_GFP] = {
      0,
  };
  uint_t remainder[2 * WORDS_PER_GFP] = {
      0,
  };

  bigint_multiply_var(product, a, b, prime_data->words, prime_data->words);
  /* bigint_clear_var( extended_prime + prime_data->words, prime_data->words ); */
  bigint_copy_var(extended_prime, prime_data->prime, prime_data->words);
  bigint_divide_simple_var(quotient, remainder, product, extended_prime, 2 * WORDS_PER_GFP);
  bigint_copy_var(res, remainder, prime_data->words);
}

/**
 * Stupidly calculate a-=prime until a < prime
 * @param a the parameter to reduce
 * @param prime_data the prime number data to reduce the result
 */
void gfp_reduce(gfp_t a, const gfp_prime_data_t* prime_data)
{
  while (bigint_compare_var(a, prime_data->prime, prime_data->words) >= 0)
  {
    bigint_subtract_var(a, a, prime_data->prime, prime_data->words);
  }
}

/**
 * Binary euclidean inversion algorithm. Alg. 2.22 in Guide to ECC.
 * Note that this algorithm does only guarantee to work for prime fields!
 * @param result the inverted number
 * @param to_invert the number to invert
 * @param prime_data the prime number data to reduce the result
 */
void gfp_binary_euclidean_inverse(gfp_t result, const gfp_t to_invert,
                                  const gfp_prime_data_t* prime_data)
{
  gfp_t u;
  gfp_t v;
  gfp_t x1;
  gfp_t x2;
  int cmp1, cmp2, carry;

  if (bigint_is_zero_var(to_invert, prime_data->words))
    return;

  bigint_copy_var(u, to_invert, prime_data->words);
  bigint_copy_var(v, prime_data->prime, prime_data->words);
  bigint_clear_var(x1, prime_data->words);
  x1[0] = 1;
  bigint_clear_var(x2, prime_data->words);

  while (1)
  {
    cmp1 = bigint_is_one_var(u, prime_data->words);
    cmp2 = bigint_is_one_var(v, prime_data->words);
    if ((cmp1 == 1) || (cmp2 == 1))
      break;

    while (BIGINT_IS_EVEN(u))
    {
      bigint_shift_right_one_var(u, u, prime_data->words);
      carry = 0;
      if (BIGINT_IS_ODD(x1))
      {
        carry = bigint_add_var(x1, x1, prime_data->prime, prime_data->words);
      }
      bigint_shift_right_one_var(x1, x1, prime_data->words);
      if (carry == 1)
      {
        x1[prime_data->words - 1] |= 1 << (BITS_PER_WORD - 1);
      }
    }

    while (BIGINT_IS_EVEN(v))
    {
      bigint_shift_right_one_var(v, v, prime_data->words);
      carry = 0;
      if (BIGINT_IS_ODD(x2))
      {
        carry = bigint_add_var(x2, x2, prime_data->prime, prime_data->words);
      }
      bigint_shift_right_one_var(x2, x2, prime_data->words);
      if (carry == 1)
      {
        x2[prime_data->words - 1] |= 1 << (BITS_PER_WORD - 1);
      }
    }

    if (bigint_compare_var(u, v, prime_data->words) >= 0)
    {
      bigint_subtract_var(u, u, v, prime_data->words);
      /* bigint_subtract(x1, x1, x2); */
      gfp_gen_subtract(x1, x1, x2, prime_data);
    }
    else
    {
      bigint_subtract_var(v, v, u, prime_data->words);
      /* bigint_subtract(x2, x2, x1); */
      gfp_gen_subtract(x2, x2, x1, prime_data);
    }
  }
  /* if u == 1*/
  if (cmp1 == 1)
  {
    bigint_copy_var(result, x1, prime_data->words);
  }
  else
  {
    bigint_copy_var(result, x2, prime_data->words);
  }
  gfp_reduce(result, prime_data);
}
