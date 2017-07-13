#include "dfa.h"

/**
 * Detect:
 *   - that in which column the fault is injected, and
 *   - the mode of operations, i.e., encryption or decryption
 *
 * Return the column index if the output is valid, and -1 otherwise
 **/
int get_fault_column(const byte * output,
                     const byte * fault_output,
                     enc_mode * mode)
{
  byte xor;
  int cnt=0;
  byte flag[16] = {0};
  
  // get inject positions
  LOOP16(i) {
    xor = output[i] ^ fault_output[i];
    if (xor) {
      cnt++;
      if (cnt > 4) {
        return -1;
      }
      flag[i] = 1;
    }
  }
  if (cnt < 4) {
    return -1;
  }

  if (flag[0] && flag[7] && flag[10] && flag[13]) {
    *mode = ENC;
    return 0;
  } else if (flag[1] && flag[4] && flag[11] && flag[14]) {
    *mode = ENC;
    return 1;
  } else if (flag[2] && flag[5] && flag[8] && flag[15]) {
    *mode = ENC;
    return 2;
  } else if (flag[3] && flag[6] && flag[9] && flag[12]) {
    *mode = ENC;
    return 3;
  } else if (flag[0] && flag[5] && flag[10] && flag[15]) {
    *mode = DEC;
    return 0;
  } else if (flag[3] && flag[4] && flag[9] && flag[14]) {
    *mode = DEC;
    return 1;
  } else if (flag[2] && flag[7] && flag[8] && flag[13]) {
    *mode = DEC;
    return 2;
  } else if (flag[1] && flag[6] && flag[11] && flag[12]) {
    *mode = DEC;
    return 3;
  }

  return -1;
}

int attack_one_column_and_fault_in_one_row(byte * output,
					   byte * fault_output,
					   int column,
					   int row,
					   enc_mode mode,
					   unsigned int * guessed_keys)
{
  // table
  const byte * tbl;

  // extract the different column
  byte o[4], fo[4], xor[4];
  o[0] = output[column<<2];          // [x<<2] => [4x] 
  o[2] = output[(10+(column<<2))%16];
  fo[0] = fault_output[column<<2];        
  fo[2] = fault_output[(10+(column<<2))%16];

  if (mode == ENC) {
    o[1] = output[(7+(column<<2))%16];
    o[3] = output[(13+(column<<2))%16];
    fo[1] = fault_output[(7+(column<<2))%16];
    fo[3] = fault_output[(13+(column<<2))%16];

    tbl = sbox;
  } else {
    o[1] = output[(5+(column<<2))%16];
    o[3] = output[(15+(column<<2))%16];
    fo[1] = fault_output[(5+(column<<2))%16];
    fo[3] = fault_output[(15+(column<<2))%16];

    tbl = rsbox;
  }

  LOOP(i, 4) {
    xor[i] = o[i] ^ fo[i];
    if (xor[i] == 0) {
      printf("Not a good fault injection for column %d, row %d, continue on next column...\n", column, row);
      return -1;
    }
  }

  byte z[4],y[4];
  int counter = 0;
  LOOP(f, 0xff) { // fault value
    byte f1 = (byte)f;
    byte f2 = gf_mul2_tbl[f1];
    if (mode == ENC) {
      z[3-row] = f1;
      z[(4-row)%4] = f2;
      z[(5-row)%4] = f1^f2;
      z[(6-row)%4] = z[3-row];
    } else {
      byte f4 = gf_mul2_tbl[f2];
      byte f8 = gf_mul2_tbl[f4];
      z[row] = f8 ^ f4 ^ f2;
      z[(row+1)%4] = f8 ^ f1;
      z[(row+2)%4] = f8 ^ f4 ^ f1;
      z[(row+3)%4] = f8 ^ f2 ^ f1;
    }

    // for k0
    LOOP(k0, 0xff) {
      y[0] = (byte)k0;
      if ((tbl[y[0]]^tbl[y[0]^z[0]]) == xor[0]) {
	// for k1
	LOOP(k1, 0xff) {
	  y[1] = (byte)k1;
	  if ((tbl[y[1]]^tbl[y[1]^z[1]]) == xor[1]) {
	    // for k2
	    LOOP(k2, 0xff) {
	      y[2] = (byte)k2;
	      if ((tbl[y[2]]^tbl[y[2]^z[2]]) == xor[2]) {
		// for k3
		LOOP(k3, 0xff) {
		  y[3] = (byte)k3;
		  if ((tbl[y[3]]^tbl[y[3]^z[3]]) == xor[3]) {
		    guessed_keys[counter++] =
		      (((unsigned int)(tbl[y[0]]^o[0]))<<24)
		      ^ (((unsigned int)(tbl[y[1]]^o[1]))<<16)
		      ^ (((unsigned int)(tbl[y[2]]^o[2]))<<8)
		      ^ ((unsigned int)(tbl[y[3]]^o[3]));
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }

  return counter;
}

int dfa_aes_one_column_attacking(int column,
				 enc_mode mode,
				 byte * output,
				 byte valid_faults[][16],
				 byte * last_round_key)
{
  unsigned int guessed_keys_1[1000] = {0};
  unsigned int guessed_keys_2[1000] = {0};

  int success_count = 0;
  LOOP(row, 4) {
    int cnt1 = attack_one_column_and_fault_in_one_row(output,
						      valid_faults[0],
						      column, row, mode,
						      guessed_keys_1);
    int cnt2 = attack_one_column_and_fault_in_one_row(output,
						      valid_faults[1],
						      column, row, mode,
						      guessed_keys_2);

    if (cnt1 <= 0 || cnt2 <= 0) {
      logging(DEBUG, "fault injected for column %d is not in row %d!", column, row);
      continue;
    }

    int i, j;
    bool manual;
    LOOP(i, cnt1) {
      LOOP(j, cnt2) {
	if (guessed_keys_1[i] == guessed_keys_2[j]) {
	  success_count += 1;
	  // todo possible keys
	  last_round_key[4*column] = (byte)(guessed_keys_1[i] >> 24);
	  last_round_key[((mode == ENC?7:5)+4*column)%16] = (byte)((guessed_keys_1[i] >> 16) & 0xff);
	  last_round_key[(10+4*column)%16] = (byte)((guessed_keys_1[i] >> 8) & 0xff);
	  last_round_key[((mode == ENC?13:15)+4*column)%16] = (byte)(guessed_keys_1[i] & 0xff);
	  printf("Possible keys each key byte:\n");
	  printf("   %2d %2d %2d %2d\n",4*column, ((mode == ENC?7:5)+4*column)%16,(10+4*column)%16,((mode == ENC?13:15)+4*column)%16);
	  printf("0x %02x %02x %02x %02x\n",(byte)(guessed_keys_1[i] >> 24), (byte)((guessed_keys_1[i] >> 16) & 0xff),(byte)((guessed_keys_1[i] >> 8) & 0xff),
		 (byte)(guessed_keys_1[i] & 0xff));
	}
      }
    }
  }

  return success_count;
}

int dfa_aes128_r7(enc_mode mode,
		  int faults_num,
		  const char * input_hex,
		  const char * output_hex,
		  const char * fault_output_hex[],
		  byte * last_round_key)
{
  if (mode == DEC) {
    logging(OFF, ANSI_COLOR_YELLOW "we don't support decryption yet" ANSI_COLOR_CYAN); 
  }

  byte output[16];
  byte valid_fault_outputs[2][16];
  hex_to_byte(output_hex, output, 16);
  LOOP(i, faults_num) {
    enc_mode f_mode;
    byte fault_output[16];
    hex_to_byte(fault_output_hex[i], fault_output, 16);
    memcpy(valid_fault_outputs[i], fault_output, 16);
  }

  LOOP(column,4) {
    int cnt;
    cnt = dfa_aes_one_column_attacking(column, mode, output, valid_fault_outputs, last_round_key);  
    if (cnt == 1) {
      logging(OFF, "Key guess for column %d is success!", column);
    } else if (cnt <= 0) {
      logging(OFF, "No key guess for column %d!", column);
    } else {
      logging(OFF, "Key guess for column %d is success for multiple cases! "
	      "Please create an issue or pull request to deal with this case.", 1);
    }
  }


  return 0;
}

int dfa_aes_one_column(int column,
		       enc_mode mode,
		       int faults_num,
		       const char * input_hex,
		       const char * output_hex,
		       const char * fault_output_hex[],
		       byte * last_round_key)
{
  byte output[16];
  hex_to_byte(output_hex, output, 16);

  int valid_count = 0;
  byte valid_fault_outputs[2][16];

  LOOP(i, faults_num) {
    enc_mode f_mode;
    byte fault_output[16];
    hex_to_byte(fault_output_hex[i], fault_output, 16);
    int c = get_fault_column(output, fault_output, &f_mode);
    if (c != column || mode != f_mode) {
      logging(WARNING, ANSI_COLOR_YELLOW "the %d-th output" ANSI_COLOR_CYAN " %s "
	      ANSI_COLOR_YELLOW "is invalid and discarded." ANSI_COLOR_RESET,
	      i+1, fault_output_hex[i]);
      continue;
    }

    logging(INFO, ANSI_COLOR_GREEN "the %d-th output" ANSI_COLOR_MAGENTA " %s "
	    ANSI_COLOR_GREEN "is injected in column" ANSI_COLOR_MAGENTA " %d"
	    ANSI_COLOR_GREEN "." ANSI_COLOR_RESET, i+1, fault_output_hex[i], c);

    valid_count++;
    if (valid_count > 2) {
      logging(DEBUG, "we have enough trace for column %d, discard the %d-th output", column, i+1);
      break;
    }
    memcpy(valid_fault_outputs[valid_count-1], fault_output, 16);
  }
  // recover the last round key for each column
  if (valid_count < 2) {
    logging(OFF, "we don't collect enough pairs for recovering the key in column "
	    ANSI_COLOR_RED "%d" ANSI_COLOR_RESET ".", column);
    return -1;
  }

  int cnt=dfa_aes_one_column_attacking(column, mode, output, valid_fault_outputs, last_round_key);
  if (cnt == 1) {
    logging(OFF, "Key guess for column %d is success!", column);
  } else if (cnt <= 0) {
    logging(DEBUG, "No key guess for column %d!", column);
  } else {
    logging(OFF, "Key guess for column %d is success for multiple cases! "
	    "Please create an issue or pull request to deal with this case.", 1);
  }

  return cnt;
}
