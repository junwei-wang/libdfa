#include "dfa.h"
#include <assert.h>
#include <stdio.h>

void test_aes_128_encryption() {
  byte last_round_key[16];

  char * p0 = "000102030405060708090a0b0c0d0e0f";
  char * c0 = "C6E5A95DDD8FCCF407606551B25CF4B0";
  const char * fc0[] = {
    "F2E5A95DDD8FCC6A07604251B245F4B0",
    "AEE5A95DDD8FCCDE0760C351B2B7F4B0",
  };
  dfa_aes_one_column(0, ENC, sizeof(fc0)/sizeof(c0),
		     p0, c0, fc0, last_round_key);
  
  char * c1 = "AD7FFC5A7444963A20E70DFC65559595";
  const char * fc1[] = {
    "ADA5FC5A2944963A20E70DB16555B995",
    "ADB8FC5A9B44963A20E70D686555DC95",
  };
  dfa_aes_one_column(1, ENC, sizeof(fc1)/sizeof(c1),
		     NULL, c1, fc1, last_round_key);

  char * p2 = "000102030405060708090a0b0c0d0e0f";
  char * c2 = "F0B6625358F698F6BE91E11D0705DA3D";
  const char * fc2[] = {
    "F0B6E35358EF98F64991E11D0705DA67",
    "F0B6ED53589298F65291E11D0705DA0E",
  };
  dfa_aes_one_column(2, ENC, sizeof(fc2)/sizeof(c2),
		     NULL, c2, fc2, last_round_key);
  
  char * p3 = "000102030405060708090a0b0c0d0e0f";
  char * c3 = "C6E5A95DDD8FCCF407606551B25CF4B0";
  const char * fc3[] = {
    "C6E5A9FBDD8F96F407206551F35CF4B0",
    "C6E5A904DD8F94F407C16551C25CF4B0",
  };
  dfa_aes_one_column(3, ENC, sizeof(fc3)/sizeof(c3),
		     NULL, c3, fc3, last_round_key);

  
  byte aes_key[16];
  reverse_aes128_key(last_round_key, aes_key, 10);

  char * true_key = "6a8bc7f750677a0b716697009a3fbbb0";
  byte true_key_bytes[16] = {0};
  hex_to_byte(true_key, true_key_bytes, 16);
  assert(compare_bytes_array(true_key_bytes, aes_key, 16) == true);
}

void test_aes128_enc_r7() {
  byte last_round_key[16];

  char * p = "00112233445566778899aabbccddeeff";
  char * c = "69c4e0d86a7b0430d8cdb78070b4c55a";
  const char * fc[] = {
    "de515f7e75c74fcba62c78a0877f0f01",
    "c329956524f05a6ca0dc7cf0c6769553",
  };

  dfa_aes128_r7(ENC, sizeof(fc)/sizeof(c),
		p, c, fc, last_round_key);
  
  byte aes_key[16];
  reverse_aes128_key(last_round_key, aes_key, 10);

  char * true_key = "000102030405060708090a0b0c0d0e0f";
  byte true_key_bytes[16] = {0};
  hex_to_byte(true_key, true_key_bytes, 16);

  assert(compare_bytes_array(true_key_bytes, aes_key, 16) == true);
}


void test_aes_128_decryption() {
  byte key[16];

  char *c =
    "c6e5a95ddd8fccf407606551b25cf4b0";
  const char * fc0[] = {
    "7ce5a95ddd26ccf407600551b25cf417",
    "fde5a95ddd3bccf40760eb51b25cf409",
  };
  dfa_aes_one_column(0, DEC, sizeof(fc0)/sizeof(c),
  		     NULL, c, fc0, key);

  const char * fc1[] = {
    "c6e5a9f5ba8fccf4076e6551b25c87b0",
    "c6e5a9d0b38fccf407536551b25c03b0"
  };
  dfa_aes_one_column(1, DEC, sizeof(fc1)/sizeof(c),
  		     NULL, c, fc1, key);

  const char * fc2[] = {
    "c6e57c5ddd8fcc4115606551b2b3f4b0",
    "c6e55a5ddd8fcc49ee606551b2b5f4b0"
  };
  dfa_aes_one_column(2, DEC, sizeof(fc2)/sizeof(c),
  		     NULL, c, fc2, key);

  byte c3_out[] = {0xb2, 0xe5, 0xcc, 0x51}; // 12, 1, 6, 11
  byte c3_f1[] =  {0x3b, 0xc2, 0xf9, 0x57};
  byte c3_f2[] =  {0x37, 0x7a, 0xe2, 0xd8};
  const char * fc3[] = {
    "c6c2a95ddd8ff9f4076065573b5cf4b0",
    "c67aa95ddd8fe2f4076065d8375cf4b0"
  };
  dfa_aes_one_column(3, DEC, sizeof(fc3)/sizeof(c),
  		     NULL, c, fc3, key);

  char * true_key = "19bd0c0b95142a7c903de8eae8ba0ca8";
  byte true_key_bytes[16] = {0};
  hex_to_byte(true_key, true_key_bytes, 16);
  assert(compare_bytes_array(true_key_bytes, key, 16) == true);
}


int main(void)
{
  test_aes_128_encryption();
  test_aes_128_decryption();
  test_aes128_enc_r7();
  printf(ANSI_COLOR_YELLOW "All tests passed.\n" ANSI_COLOR_RESET);
  return 0;
}
