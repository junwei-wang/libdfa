#ifndef _DFA_H_
#define _DFA_H_

#include "common.h"
#include "gf.h"
#include "aes.h"
#include <stdlib.h>

int dfa_aes_one_column(int column,
		       enc_mode mode,
		       int num_faluts,
		       const char * input_hex,
		       const char * output_hex,
		       const char * falut_output_hex[],
		       byte * last_round_key);

int dfa_aes128_r7(enc_mode mode,
		  int faults_num,
		  const char * input_hex,
		  const char * output_hex,
		  const char * fault_output_hex[],
		  byte * last_round_key);

#endif//_DFA_H

