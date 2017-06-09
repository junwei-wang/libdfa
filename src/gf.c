#include "gf.h"


/**
 * from http://www.samiam.org/galois.html
 **/
byte gf_mul(byte a, byte b)
{
  byte p = 0;
  byte counter;
  byte hi_bit_set;
  for(counter = 0; counter < 8; counter++) {
    if((b & 1) == 1) 
      p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if(hi_bit_set == 0x80) 
      a ^= 0x1b;		
    b >>= 1;
  }
  return p;
}

/**
 * We did multiplication by following proceduer.
 * left shift val one bit, if it is bigger that 255, then xor with 0x11b.
 **/
byte gf_mul2(byte val)
{
  signed char temp;

  temp = (signed char) val;
  temp >>= 7;
  temp &= 0x1b;

  return (val<<1) ^ temp;
}
