#include "aes.h"

void reverse_aes128_key(byte * round_key,
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
