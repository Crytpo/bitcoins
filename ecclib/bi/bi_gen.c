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

#include "bi_gen.h"

#include <string.h>

const gfp_t bigint_one = {
    1,
};
const gfp_t bigint_zero = {
    0,
};

/**
 * Adds two big integers with variable length
 * @param a the first parameter to add
 * @param b the second parameter to add
 * @param res the result
 * @param length the number of uint_t to add
 * @return the carry flag
 */
int bigint_add_var(uint_t* res, const uint_t* a, const uint_t* b, const int length)
{
  ulong_t temp = 0;
  int i        = 0;
  for (; i < length; i++)
  {
    temp += *a;
    temp += *b;
    *res = (uint_t)temp;
    temp >>= BITS_PER_WORD;
    a++;
    b++;
    res++;
  }
  return temp;
}

/**
 * Adds two big integers with variable length
 * @param a the first parameter to add
 * @param b the second parameter to add
 * @param res the result
 * @param length the number of uint_t to add
 * @param carry input carry flag
 * @return the carry flag
 */
int bigint_add_carry_var(uint_t* res, const uint_t* a, const uint_t* b, const int length,
                         const int carry)
{
  slong_t temp = carry;
  int i        = 0;
  for (; i < length; i++)
  {
    temp += *a;
    temp += *b;
    *res = (uint_t)temp;
    temp >>= BITS_PER_WORD;
    a++;
    b++;
    res++;
  }
  return temp;
}

/**
 * Subtracts two big integers with variable length: res = a - b
 * @param a the minuend
 * @param b the subtrahend
 * @param res the difference
 * @param length the number of uint_t elements to subtract
 * @return the carry flag
 */
int bigint_subtract_var(uint_t* res, const uint_t* a, const uint_t* b, const int length)
{
  slong_t temp = 0;
  int i        = 0;
  for (; i < length; i++)
  {
    temp += *a;
    temp -= *b;
    *res = (uint_t)temp;
    temp >>= BITS_PER_WORD;
    a++;
    b++;
    res++;
  }
  return temp;
}

/**
 * Subtracts two big integers with variable length: res = a - b
 * @param a the minuend
 * @param b the subtrahend
 * @param res the difference
 * @param length the number of uint_t elements to subtract
 * @return the carry flag
 */
int bigint_subtract_carry_var(uint_t* res, const uint_t* a, const uint_t* b, const int length,
                              const int carry)
{
  slong_t temp = carry;
  int i        = 0;
  for (; i < length; i++)
  {
    temp += *a;
    temp -= *b;
    *res = (uint_t)temp;
    temp >>= BITS_PER_WORD;
    a++;
    b++;
    res++;
  }
  return temp;
}

/**
 * Shifts a biginteger to the left
 * @param res destination big integer
 * @param a the data to shift
 * @param left the number of bits to shift
 * @param length number of words which should be shifted (size of a & res)
 */
void bigint_shift_left_var(uint_t* res, const uint_t* a, const int left, const int length)
{
  uint_t temp, temp2;
  int i, nWords, nBits;

  if (length < 0)
    return;
  if (left < 0)
    bigint_shift_right_var(res, a, -left, length);

  nWords = left >> LD_BITS_PER_WORD;
  nBits  = left & (BITS_PER_WORD - 1);

  res += length - 1;
  a += length - 1 - nWords;
  if (nBits != 0)
  {
    temp = *a-- << nBits;
    for (i = length - 2 - nWords; i >= 0; i--)
    {
      temp2 = *a--;
      temp |= temp2 >> (BITS_PER_WORD - nBits);
      *res-- = temp;
      temp   = temp2 << nBits;
    }
    *res-- = temp;
  }
  else
  {
    for (i = length - 1; i >= nWords; i--)
    {
      *res-- = *a--;
    }
  }
  for (i = nWords - 1; i >= 0; --i)
    *res-- = 0;
}

/**
 * Shifts a biginteger to the right
 * @param res the destination big integer
 * @param a the data to shift
 * @param right the number of bits to shift
 * @param length number of words in a and res
 */
void bigint_shift_right_var(uint_t* res, const uint_t* a, const int right, const int length)
{
  uint_t temp, temp2;
  int i, nWords, nBits;

  if (length < 0)
    return;
  if (right < 0)
    bigint_shift_left_var(res, a, -right, length);

  nWords = right >> LD_BITS_PER_WORD;
  nBits  = right & (BITS_PER_WORD - 1);

  if (nBits == 0)
  {
    for (i = 0; i < (length - nWords); i++)
    {
      res[i] = a[i + nWords];
    }
  }
  else
  {
    temp = a[nWords] >> nBits;
    for (i = 1; i < (length - nWords); i++)
    {
      temp2 = a[nWords + i];
      /* WARNING gcc has a problem with (uint_t) << BITS_PER_WORD !! */
      temp |= temp2 << (BITS_PER_WORD - nBits);
      res[i - 1] = temp;
      temp       = temp2 >> nBits;
    }
    res[length - nWords - 1] = temp;
  }

  for (i   = length - nWords; i < length; i++)
    res[i] = 0;
}

/**
 * Shifts a biginteger to the right by one bit
 * @param a the data to shift
 * @param res destination big integer
 * @param length word count which should be shifted
 */
void bigint_shift_right_one_var(uint_t* res, const uint_t* a, const int length)
{
  uint_t temp, temp2;
  int i;

  if (length < 0)
    return;

  temp = a[0] >> 1;
  for (i = 1; i < length; i++)
  {
    temp2 = a[i];
    temp |= temp2 << (BITS_PER_WORD - 1);
    res[i - 1] = temp;
    temp       = temp2 >> 1;
  }
  res[length - 1] = temp;
}

/**
 * Compares two big integers with variable length.
 * @param a
 * @param b
 * @param length the size of a and b in words
 * @return -1, 0 or 1 as *a* is numerically less than, equal to, or greater than *b*.
 */
int bigint_compare_var(const uint_t* a, const uint_t* b, const int length)
{
  slong_t temp;
  int i = length - 1;
  for (; i >= 0; i--)
  {
    temp = a[i];
    temp -= b[i];
    if (temp != 0)
      return (temp > 0 ? 1 : -1);
  }
  return 0;
}

/**
 * Checks if a number is zero.
 * @param a
 * @param length the size of a in words
 * @return 1 if zero otherwise 0.
 */
int bigint_is_zero_var(const uint_t* a, const int length)
{
  int i;
  for (i = 0; i < length; i++)
  {
    if (a[i] != 0)
      return 0;
  }
  return 1;
}

/**
 * Checks if a number is one.
 * @param a
 * @param length the size of a in words
 * @return 1 if one otherwise 0.
 */
int bigint_is_one_var(const uint_t* a, const int length)
{
  int i;
  if (a[0] != 1)
    return 0;
  for (i = 1; i < length; i++)
  {
    if (a[i] != 0)
      return 0;
  }
  return 1;
}

/**
 * Multiply two big integers with variable length
 * @param a first multiplicant
 * @param b second multiplicant
 * @param result An buffer (array) with (length_a+length_b) entries is required.
 * @param length_a the size of array a
 * @param length_b the size of array b
 */
void bigint_multiply_var(uint_t* result, const uint_t* a, const uint_t* b, const int length_a,
                         const int length_b)
{
  int i, j;
  ulong_t product;
  uint_t carry;

  if (length_a < 0)
    return;
  if (length_b < 0)
    return;

  bigint_clear_var(result, length_a + length_b);
  for (i = 0; i < length_a; i++)
  {
    carry = 0;
    for (j = 0; j < length_b; j++)
    {
      product = result[i + j];
      product += (ulong_t)a[i] * (ulong_t)b[j];
      product += carry;
      result[i + j] = (product & UINT_T_MAX);
      carry         = product >> (8 * sizeof(uint_t));
    }
    result[i + length_b] = carry;
  }
}

/**
 * Sets a single specific big in a
 * @param a big integer to modify
 * @param bit bit to set
 * @param value the bit value
 * @param length the maximum size of a in words
 */
void bigint_set_bit_var(uint_t* a, const int bit, const int value, const int length)
{
  int iWord, iBit;
  uint_t word;

  if (bit < 0)
    return;

  iWord = bit >> LD_BITS_PER_WORD;
  iBit  = bit & (BITS_PER_WORD - 1);

  if (iWord >= length)
    return;

  word = a[iWord];
  word &= ~(1 << iBit);
  word |= value << iBit;
  a[iWord] = word;
}

/**
 * Returns the state of a specific bit.
 * @param a big integer to test
 * @param bit bit to test
 * @param length the maximum size of a in words
 * @return 1 if bit is 1, 0 if bit is 0, and 0 if out of bounds.
 */
int bigint_test_bit_var(const uint_t* a, const int bit, const int length)
{
  int iWord, iBit;

  if (bit < 0)
    return 0;

  iWord = bit >> LD_BITS_PER_WORD;
  iBit  = bit & (BITS_PER_WORD - 1);

  if (iWord >= length)
    return 0;

  return (a[iWord] >> iBit) & 0x01;
}

/**
 * Get the bit index of the most significant bit
 * @param a the big integer to test
 * @param param the size of the uint_t-array in words
 * @return 0 <= index < ECC_NUM_BITS, -1 if no bit is set
 */
int bigint_get_msb_var(const uint_t* a, const int length)
{
  int word, bit;
  uint_t temp;
  if (length < 0)
    return -1;
  for (word = length - 1; word > 0; word--)
  {
    temp = a[word];
    if (temp != 0)
      break;
  }
  temp = a[word];
  for (bit = BITS_PER_WORD - 1; bit >= 0; bit--)
  {
    if (((temp >> bit) & 0x01) == 1)
      break;
  }
  return word * BITS_PER_WORD + bit;
}

/**
 * Access a single byte of the big integer
 * @param a the big integer to investigate
 * @param length the length of the uint_t array
 * @param index the byte index to access
 * @return the byte to access (zero if index is out of bounds)
 */
uint8_t bigint_get_byte_var(const uint_t* a, const int length, const int index)
{
  int wordIndex = index >> LD_BYTES_PER_WORD;
  int byteIndex = index & (BYTES_PER_WORD - 1);
  uint_t word;

  /* handle out of bounds */
  if ((wordIndex < 0) || (wordIndex >= length))
    return 0;

  word = a[wordIndex];

#if (BYTES_PER_WORD == 1)
  return word;
#else
  return (word >> (byteIndex << 3)) & 0xFF;
#endif
}

/**
 * Set a single byte of a big integer
 * @param a the big integer to set
 * @param length the length of the uint_t array
 * @param index the byte index to access
 * @param value the byte to write to the specified index
 */
void bigint_set_byte_var(uint_t* a, const int length, const int index, const uint8_t value)
{
  int wordIndex = index >> LD_BYTES_PER_WORD;
  int byteIndex = index & (BYTES_PER_WORD - 1);
  uint_t word;

  /* handle out of bounds */
  if ((wordIndex < 0) || (wordIndex >= length))
    return;

#if (BYTES_PER_WORD == 1)
  word = value;
#else
  word = a[wordIndex];
  byteIndex <<= 3;
  word &= ~(0xFF << byteIndex);
  word |= value << byteIndex;
#endif
  a[wordIndex] = word;
}

/**
 * Simple bit-wise long division algorithm. Not fast nor optimal but simple.
 * @param Q Quotient
 * @param R Remainder
 * @param N Dividend
 * @param D Divisor
 * @param len
 */
void bigint_divide_simple_var(uint_t* Q, uint_t* R, const uint_t* N, const uint_t* D,
                              const int words)
{
  int i;
  if (bigint_is_zero_var(D, words))
    return;

  bigint_clear_var(Q, words);
  bigint_clear_var(R, words);
  for (i = BITS_PER_WORD * words - 1; i >= 0; i--)
  {
    bigint_shift_left_var(R, R, 1, words);
    R[0] |= bigint_test_bit_var(N, i, words);
    if (bigint_compare_var(R, D, words) >= 0)
    {
      bigint_subtract_var(R, R, D, words);
      bigint_set_bit_var(Q, i, 1, words);
    }
  }
}

/**
 * Extended Euclidian for bigints.
 * Calculates d = gcd(a,b) and x,y satisfying a*x + b*y = g.
 * @param a The first argument of the gcd
 * @param b The second argument of the gcd
 * @param g The gcd of a and b
 * @param x
 * @param y
 * @param words The number of words of each argument
 */
void bigint_extended_euclidean_var(bigint_t g, bigint_t x, bigint_t y, const bigint_t a,
                                   const bigint_t b, const int words)
{
  bigint_t u, v, x1, y1, x2, y2, q, r;
  uint_t tmp1[2 * WORDS_PER_BIGINT], tmp2[2 * WORDS_PER_BIGINT];
  bigint_clear_var(u, words);
  bigint_clear_var(v, words);
  bigint_clear_var(x1, words);
  bigint_clear_var(y1, words);
  bigint_clear_var(x2, words);
  bigint_clear_var(y2, words);
  bigint_copy_var(u, a, words);
  bigint_copy_var(v, b, words);
  x1[0] = 1;
  y2[0] = 1;
  while (!bigint_is_zero_var(u, words))
  {
    bigint_divide_simple_var(q, r, v, u, words);
    bigint_multiply_var(tmp1, q, x1, words, words);
    bigint_multiply_var(tmp2, q, y1, words, words);
    bigint_subtract_var(x, x2, tmp1, words);
    bigint_subtract_var(y, y2, tmp2, words);

    bigint_copy_var(v, u, words);
    bigint_copy_var(u, r, words);
    bigint_copy_var(x2, x1, words);
    bigint_copy_var(x1, x, words);
    bigint_copy_var(y2, y1, words);
    bigint_copy_var(y1, y, words);
  }
  bigint_copy_var(g, v, words);
  bigint_copy_var(x, x2, words);
  bigint_copy_var(y, y2, words);
}
