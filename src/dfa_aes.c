#include "aes.h"
#include "gf.h"

#include <stdio.h>

int one_column_key_guess(byte * o1,
			 byte * o2,
			 int fault_row,
			 unsigned int * key_guess) {
  byte xor[4] = {0};

  byte i;
  for (i = 0; i < 4; i++) {
    xor[i] = o1[i] ^ o2[i];
  }
  int f, k0, k1, k2, k3;
  byte z[4],y[4];

  int counter = 0;
  for (f = 0; f <= 0xff; f++) {
    z[3-fault_row] = (byte)f;
    z[(4-fault_row)%4] = gf_mul2_tbl[(byte)f];
    z[(5-fault_row)%4] = z[3-fault_row]^z[(4-fault_row)%4];
    z[(6-fault_row)%4] = z[3-fault_row];

    // for k0
    for (k0 = 0; k0 <= 0xff; k0++) {
      y[0] = (byte)k0;

      if ((sbox[y[0]]^sbox[y[0]^z[0]]) == xor[0]) {
	// for k1
	for (k1 = 0; k1 <= 0xff; k1++) {
	  y[1] = (byte)k1;
	  if ((sbox[y[1]]^sbox[y[1]^z[1]]) == xor[1]) {

	    // for k2
	    for (k2 = 0; k2 <= 0xff; k2++) {
	      y[2] = (byte)k2;
	      if ((sbox[y[2]]^sbox[y[2]^z[2]]) == xor[2]) {
		// for k3
		for (k3 = 0; k3 <= 0xff; k3++) {
		  y[3] = (byte)k3;
		  if ((sbox[y[3]]^sbox[y[3]^z[3]]) == xor[3]) {
		    key_guess[counter++] =
		      (((unsigned int)(sbox[y[0]]^o1[0]))<<24)
		      ^ (((unsigned int)(sbox[y[1]]^o1[1]))<<16)
		      ^ (((unsigned int)(sbox[y[2]]^o1[2]))<<8)
		      ^ ((unsigned int)(sbox[y[3]]^o1[3]));
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }
  return counter-1;
}


int attack_one_column(byte * origin_output,
		      byte * fault_output1,
		      byte * fault_output2,
		      byte * last_round_key,
		      int column)
{
  unsigned int key_guess_1[1000] = {0};
  unsigned int key_guess_2[1000] = {0};

  int fault_row = 0;
  for (fault_row = 0; fault_row < 4; fault_row++) {
    int keys1 = one_column_key_guess(origin_output, fault_output1, fault_row, key_guess_1);
    int keys2 = one_column_key_guess(origin_output, fault_output2, fault_row, key_guess_2);
    if (keys1 <= 0 || keys2 <= 0) {
      printf("Fault is not injected for column %d is not row %d !\n", column, fault_row);
      continue;
    }
    int i, j;
    int count = 0;
    for (i = 0; i < keys1; i++) {
      for (j = 0; j < keys2; j++) {
	if (key_guess_1[i] == key_guess_2[j]) {
	  count += 1;
	  last_round_key[4*column] = (byte)(key_guess_1[i] >> 24);
	  last_round_key[(7+4*column)%16] = (byte)((key_guess_1[i] >> 16) & 0xff);
	  last_round_key[(10+4*column)%16] = (byte)((key_guess_1[i] >> 8) & 0xff);
	  last_round_key[(13+4*column)%16] = (byte)(key_guess_1[i] & 0xff);
	}
      }
    }

    if (count > 1) {
      printf("Key guess is more than 1 for column %d if injected is row %d!\n", column, fault_row);
    }
    if (count > 0) {
      printf("Key guess for column %d is success if fault injected in row %d!\n", column, fault_row);
      return count;
    }
    if (count <= 0) {
      printf("No key guess for column %d if injected row is %d!\n", column, fault_row);
    }
  }
}

void reverse_key(byte * round_key,
		 byte * aes_key,
		 int round) {
  byte rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

  int i;
  while(round--) {
    for (i = 15; i >= 4 ; i--) {
      round_key[i] ^= round_key[i-4];
    }
    round_key[3] ^= sbox[round_key[12]];
    round_key[2] ^= sbox[round_key[15]];
    round_key[1] ^= sbox[round_key[14]];
    round_key[0] ^= sbox[round_key[13]] ^ rcon[round];
  }

  for (i = 0; i < 16; i++) {
    aes_key[i] = round_key[i];
  }
}

int main(void) {
  byte last_round_key[16] = {0};
  byte c0_out[] = {0xc6, 0xf4, 0x65, 0x5c}; // 0, 7, 10, 13
  byte c0_f1[] =  {0x5a, 0x83, 0x6b, 0x0c};
  byte c0_f2[] =  {0xf2, 0x6a, 0x42, 0x45};

  attack_one_column(c0_out, c0_f1, c0_f2, last_round_key, 0);

  byte c1_out[] = {0x74, 0xfc, 0x95, 0x7f}; // 4, 11, 14, 1
  byte c1_f1[] =  {0x9b, 0x68, 0xdc, 0xb8};
  byte c1_f2[] =  {0x29, 0xb1, 0xb9, 0xa5};
  attack_one_column(c1_out, c1_f1, c1_f2, last_round_key, 1);

  byte c2_out[] = {0xbe, 0x3d, 0x62, 0xf6}; // 8, 15, 2, 5
  byte c2_f1[] =  {0x5c, 0xf1, 0xd4, 0xa6};
  byte c2_f2[] =  {0x84, 0xb9, 0xfd, 0x37};
  attack_one_column(c2_out, c2_f1, c2_f2, last_round_key, 2);

  byte c3_out[] = {0xb2, 0x5d, 0xcc, 0x60}; // 12, 3, 6, 9
  byte c3_f1[] =  {0xf3, 0xfb, 0x96, 0x20};
  byte c3_f2[] =  {0xc2, 0x04, 0x94, 0xc1};
  attack_one_column(c3_out, c3_f1, c3_f2, last_round_key, 3);

  byte aes_key[16] = {0};
  reverse_key(last_round_key, aes_key, 10); 

  int i;
  for (i = 0; i < 16; i++) {
    printf("%02x ", aes_key[i]);
  }
  printf("\n");
}
