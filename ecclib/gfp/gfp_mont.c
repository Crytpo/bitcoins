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

#include "gfp_mont.h"
#include "../bi/bi.h"
#include "gfp_gen.h"

/**
 * Convert a normal number (mod p) into the montgomery domain.
 * @param res the resulting number
 * @param src the source number
 * @param prime_data the used prime data needed to do the conversion
 */
void gfp_normal_to_montgomery(gfp_t res, const gfp_t src, const gfp_prime_data_t* prime_data)
{
  gfp_mont_multiply(res, src, prime_data->r_squared, prime_data);
}

/**
 * Convert a number in Montgomery domain into a normal domain.
 * @param res the resulting number
 * @param src the source number
 * @param prime_data the used prime data needed to do the conversion
 */
void gfp_montgomery_to_normal(gfp_t res, const gfp_t src, const gfp_prime_data_t* prime_data)
{
  gfp_mont_multiply(res, src, bigint_one, prime_data);
}

/**
 * Montgomery multiplication
 *
 * @param res the result = a * b * R^-1 mod prime
 * @param a first operand (in montgomery domain)
 * @param b second operand (in montgomery domain)
 * @param prime_data the used prime data needed to do the multiplication
 */
void gfp_mont_multiply(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data)
{
  uint_t temp_product[2 * WORDS_PER_GFP];
  uint_t temp_buffer[2 * WORDS_PER_GFP];
  uint_t temp_buffer_2[2 * WORDS_PER_GFP];
  int carry;

  // d = a * b
  bigint_multiply_var(temp_product, a, b, prime_data->words, prime_data->words);
  // d * n = d * (p' mod R)
  bigint_multiply_var(temp_buffer, temp_product, prime_data->prime_n, prime_data->words,
                      prime_data->words);
  // (d*n) * p
  bigint_multiply_var(temp_buffer_2, temp_buffer, prime_data->prime, prime_data->words,
                      prime_data->words);
  // c = d + (d*n)*p
  carry = bigint_add_var(temp_buffer_2, temp_buffer_2, temp_product, 2 * prime_data->words);
  // c /= R
  bigint_copy_var(res, temp_buffer_2 + prime_data->words, prime_data->words);
  // check if c >= p
  if (carry || (bigint_compare_var(res, prime_data->prime, prime_data->words) >= 0))
  {
    // c -= p
    bigint_subtract_var(res, res, prime_data->prime, prime_data->words);
  }
}

/**
 * Calculate the montgomery inverse for the given globally defined constants
 * based on Hankerson p. 42
 * @param res the inverse: (a * R)^1 * R^2 mod p
 * @param a the number to invert (within the montgomery domain)
 * @param prime_data the used prime data needed to do the multiplication
 */
void gfp_mont_inverse(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data)
{
  gfp_t u;
  gfp_t v;
  gfp_t x1;
  gfp_t x2;
  int k = 0, carry = 0, length = prime_data->words;
  bigint_copy_var(u, a, length);
  bigint_copy_var(v, prime_data->prime, length);
  bigint_clear_var(x1, length);
  x1[0] = 1;
  bigint_clear_var(x2, length);

  while (!bigint_is_zero_var(v, length))
  {
    if (BIGINT_IS_EVEN(v))
    {
      bigint_shift_right_one_var(v, v, length);
      carry = bigint_add_var(x1, x1, x1, length);
    }
    else if (BIGINT_IS_EVEN(u))
    {
      bigint_shift_right_one_var(u, u, length);
      bigint_add_var(x2, x2, x2, length);
    }
    else if (bigint_compare_var(v, u, length) >= 0)
    {
      bigint_subtract_var(v, v, u, length);
      bigint_shift_right_one_var(v, v, length);
      bigint_add_var(x2, x2, x1, length);
      carry = bigint_add_var(x1, x1, x1, length);
    }
    else
    {
      bigint_subtract_var(u, u, v, length);
      bigint_shift_right_one_var(u, u, length);
      bigint_add_var(x1, x1, x2, length);
      bigint_add_var(x2, x2, x2, length);
    }
    k++;
  }
  if (carry || (bigint_compare_var(x1, prime_data->prime, length) >= 0))
  {
    bigint_subtract_var(x1, x1, prime_data->prime, length);
  }

  /* at this point x1 = a^1 * 2^k mod prime */
  /* n <= k <= 2*n */

  if (k < (BITS_PER_WORD * length))
  {
    bigint_copy_var(x2, x1, length); /* needed in case of future gfp_mont_multiply optimizations */
    gfp_mont_multiply(x1, x2, prime_data->r_squared, prime_data);
    k += (BITS_PER_WORD * length);
  }
  /* now k >= Wt */
  gfp_mont_multiply(res, x1, prime_data->r_squared, prime_data);
  if (k > (BITS_PER_WORD * length))
  {
    k = (2 * BITS_PER_WORD * length) - k;
    bigint_clear_var(x2, length);
    bigint_set_bit_var(x2, k, 1, length);
    bigint_copy_var(x1, res, length); /* needed in case of future gfp_mont_multiply optimizations */
    gfp_mont_multiply(res, x1, x2, prime_data);
  }
}

/**
 * Perform an exponentiation with a custom modulus and custom length. Does not support a==res.
 * @param res a^exponent mod modulus
 * @param a
 * @param exponent
 * @param exponent_length the number of words needed to represent the exponent
 * @param prime_data the used prime data needed to do the multiplication
 */
void gfp_mont_exponent(gfp_t res, const gfp_t a, const uint_t* exponent, const int exponent_length,
                       const gfp_prime_data_t* prime_data)
{
  int bit;

  bigint_copy_var(res, prime_data->gfp_one, prime_data->words);
  for (bit = bigint_get_msb_var(exponent, exponent_length); bit >= 0; bit--)
  {
    /* gfp_mont_multiply( res, res, res, prime_data ); */
    gfp_mont_square(res, res, prime_data);
    if (bigint_test_bit_var(exponent, bit, exponent_length) == 1)
    {
      gfp_mont_multiply(res, res, a, prime_data);
    }
  }
}

/**
 * Compute the constant R, needed for montgomery multiplications
 * @param res the param R mod prime
 * @param prime_data the prime number data to reduce the result
 */
void gfp_mont_compute_R(gfp_t res, gfp_prime_data_t* prime_data)
{
  size_t i;
  bigint_clear_var(res, prime_data->words);
  bigint_set_bit_var(res, prime_data->bits - 1, 1, prime_data->words);

  for (i = prime_data->bits - 1; i < prime_data->words * BITS_PER_WORD; i++)
  {
    gfp_gen_add(res, res, res, prime_data);
  }
}

/**
 * Compute the constant R^2, needed for montgomery multiplications
 * @param res the param R^2 mod prime
 * @param prime_data the prime number data to reduce the result
 */
void gfp_mont_compute_R_squared(gfp_t res, gfp_prime_data_t* prime_data)
{
  size_t i;
  bigint_clear_var(res, prime_data->words);
  bigint_set_bit_var(res, prime_data->bits - 1, 1, prime_data->words);

  for (i = prime_data->bits - 1; i < (2 * prime_data->words * BITS_PER_WORD); i++)
  {
    gfp_gen_add(res, res, res, prime_data);
  }
}

/**
 * Computes the constant prime_n required for montgomery multiplications and stores
 * it directly into the prime_data structure.
 * @param prime_data the prime that is used for future montgomery multiplications
 * prime_n = -p^(-1) (mod R)
 */
void gfp_mont_compute_n(gfp_prime_data_t* prime_data)
{

  uint_t temp[2 * WORDS_PER_GFP];
  uint_t temp2[2 * WORDS_PER_GFP];
  int i;

  bigint_clear_var(temp, prime_data->words);
  temp[0] = 1;

  // invert the prime using Euler's theorem: phi(p^k) = p^k − p^{k−1} = p^{k−1}(p − 1)
  // ... a lot of room for performance optimization ...
  for (i = 1; i < BITS_PER_WORD * prime_data->words; i++)
  {
    bigint_multiply_var(temp2, temp, temp, prime_data->words, prime_data->words);
    bigint_multiply_var(temp, temp2, prime_data->prime, prime_data->words, prime_data->words);
  }
  bigint_clear_var(prime_data->prime_n, WORDS_PER_GFP);
  bigint_subtract_var(prime_data->prime_n, prime_data->prime_n, temp, prime_data->words);
}

/**
 * Computes the constant n0' required for montgomery multiplications.
 * @param prime_data the prime that is used for future montgomery multiplications
 * @return the constant n0'
 */
uint_t gfp_mont_compute_n0(const gfp_prime_data_t* prime_data)
{
  size_t i;
  uint_t t = 1;

  for (i = 1; i < BITS_PER_WORD; i++)
  {
    t = t * t;
    t = t * prime_data->prime[0];
  }
  t = -t;
  return t;
}

/**
 * Use two montgomery multiplications to compute a * b mod prime
 *   T1 = a * b * R^-1
 *   res = T1 * R^2 * R^-1 = a * b
 * @param res the result = a * b  mod prime (not in Montgomery domain)
 * @param a first operand (not in Montgomery domain)
 * @param b second operand (not in Montgomery domain)
 * @param prime_data the used prime data needed to do the multiplication
 */
void gfp_mult_two_mont(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data)
{
  gfp_mont_multiply(res, a, b, prime_data);
  gfp_mont_multiply(res, res, prime_data->r_squared, prime_data);
}

void gfp_mont_square(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data)
{
  uint_t temp_product[2 * WORDS_PER_GFP] = {
      0,
  };
  uint_t temp_buffer[2 * WORDS_PER_GFP] = {
      0,
  };
  uint_t temp_buffer_2[2 * WORDS_PER_GFP] = {
      0,
  };
  int carry;

  // d = a^2
  bigint_multiply_var(temp_product, a, a, prime_data->words, prime_data->words);
  // d * n = d * (p' mod R)
  bigint_multiply_var(temp_buffer, temp_product, prime_data->prime_n, prime_data->words,
                      prime_data->words);
  // (d*n) * p
  bigint_multiply_var(temp_buffer_2, temp_buffer, prime_data->prime, prime_data->words,
                      prime_data->words);
  // c = d + (d*n)*p
  carry = bigint_add_var(temp_buffer_2, temp_buffer_2, temp_product, 2 * prime_data->words);
  // c /= R
  bigint_copy_var(res, temp_buffer_2 + prime_data->words, prime_data->words);
  // check if c >= p
  if (carry || (bigint_compare_var(res, prime_data->prime, prime_data->words) >= 0))
  {
    // c -= p
    bigint_subtract_var(res, res, prime_data->prime, prime_data->words);
  }
}
