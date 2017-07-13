#include "aes.h"

void reverse_aes128_key(byte * round_key,
			byte * aes_key,
			int round) {
  byte rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

  int i;
  for (i = 0; i < 16; i++) {
    aes_key[i] = round_key[i];
  }

  while(round--) {
    for (i = 15; i >= 4 ; i--) {
      aes_key[i] ^= aes_key[i-4];
    }
    aes_key[3] ^= sbox[aes_key[12]];
    aes_key[2] ^= sbox[aes_key[15]];
    aes_key[1] ^= sbox[aes_key[14]];
    aes_key[0] ^= sbox[aes_key[13]] ^ rcon[round];
  }

}
